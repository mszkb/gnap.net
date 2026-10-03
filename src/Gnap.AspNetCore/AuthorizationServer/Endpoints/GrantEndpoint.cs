using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>The grant endpoint (RFC 9635 Section 2): <c>POST {BasePath}/tx</c>.</summary>
internal sealed class GrantEndpoint(
    IGrantStore grantStore,
    IClientKeyStore clientKeyStore,
    IGrantPolicy policy,
    GrantIssuer issuer,
    KeyProofVerifier proofVerifier,
    GnapEndpointUris uris,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<GrantEndpoint> logger)
{
    /// <summary>The interaction start modes this AS supports.</summary>
    public static readonly string[] SupportedStartModes = [StartModes.Redirect, StartModes.UserCode, StartModes.UserCodeUri];

    /// <summary>The interaction finish methods this AS supports.</summary>
    public static readonly string[] SupportedFinishMethods = [FinishMethods.Redirect, FinishMethods.Push];

    private const string UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ";
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public async Task HandleAsync(HttpContext context)
    {
        var body = await Protocol.ReadBodyAsync(context, _options.MaxRequestBodySize).ConfigureAwait(false);
        if (body is null || body.Length == 0)
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return;
        }

        GrantRequest? request;
        try
        {
            request = JsonSerializer.Deserialize(body, GnapJsonContext.Default.GrantRequest);
        }
        catch (JsonException e)
        {
            logger.LogInformation("Rejected grant request: malformed JSON ({Reason}).", e.Message);
            request = null;
        }

        if (request?.Client is null)
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return;
        }

        // Authenticate first: nothing about the request is evaluated for an unproven client.
        var client = await ResolveClientAsync(request.Client, context.RequestAborted).ConfigureAwait(false);
        if (client is null || !await proofVerifier.VerifyAsync(context, body, client.Key, "grant request").ConfigureAwait(false))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidClient).ConfigureAwait(false);
            return;
        }

        if (Validate(request) is { } validationError)
        {
            await Protocol.WriteErrorAsync(context, validationError).ConfigureAwait(false);
            return;
        }

        var now = _options.TimeProvider.GetUtcNow();
        var grant = new GrantRecord
        {
            Id = Protocol.NewSecret(16),
            CreatedAt = now,
            Request = request,
            ClientKey = client.Key,
            InstanceId = client.InstanceId,
            ClientClassId = client.ClassId,
            ClientDisplay = client.Display,
            ClientIsRegistered = client.IsRegistered,
            GrantEndpointUri = uris.GrantEndpoint(context),
        };

        var canInteract = request.Interact?.Start?.Any(s => SupportedStartModes.Contains(s.Mode)) is true;
        var decision = await policy.EvaluateAsync(
            new GrantPolicyContext { HttpContext = context, Client = client, Request = request, CanInteract = canInteract },
            context.RequestAborted).ConfigureAwait(false);

        switch (decision.Kind)
        {
            case GrantDecisionKind.Approve:
                if (!ApprovalFits(decision.Approval!, request))
                {
                    throw new InvalidOperationException("GrantApproval.Access must contain one entry per requested access token.");
                }

                grant.TransitionTo(GrantState.Approved);
                grant.Approval = decision.Approval;
                var (response, _) = await issuer.FinalizeAsync(context, grant).ConfigureAwait(false);
                await grantStore.CreateAsync(grant, context.RequestAborted).ConfigureAwait(false);
                await Protocol.WriteAsync(context, StatusCodes.Status200OK, response).ConfigureAwait(false);
                return;

            case GrantDecisionKind.RequireInteraction when canInteract:
                grant.TransitionTo(GrantState.Pending);
                var interact = await StartInteractionAsync(context, grant, now).ConfigureAwait(false);
                var continuation = issuer.RotateContinuation(context, grant, grant.InteractionExpiresAt!.Value);
                await grantStore.CreateAsync(grant, context.RequestAborted).ConfigureAwait(false);
                await Protocol.WriteAsync(context, StatusCodes.Status200OK, new GrantResponse
                {
                    Interact = interact,
                    Continue = continuation,
                    InstanceId = null,
                }).ConfigureAwait(false);
                return;

            default:
                // Denied, or interaction required but the client cannot interact.
                var error = decision.Kind == GrantDecisionKind.Deny ? decision.Error : GnapErrorCode.RequestDenied;
                grant.TransitionTo(GrantState.Revoked);
                grant.DenialCode = error.Value;
                grant.DenialReported = true;
                await grantStore.CreateAsync(grant, context.RequestAborted).ConfigureAwait(false);
                await Protocol.WriteErrorAsync(context, error).ConfigureAwait(false);
                return;
        }
    }

    internal static bool ApprovalFits(GrantApproval approval, GrantRequest request) =>
        approval.Access is null || approval.Access.Count == (request.AccessToken?.Count ?? 0);

    private async Task<ClientIdentity?> ResolveClientAsync(ClientInstance client, CancellationToken cancellationToken)
    {
        GnapKey? key;
        string? instanceId = null;
        var classId = client.ClassId;
        var display = client.Display;
        var registered = false;

        if (client.IsReference)
        {
            var registration = await clientKeyStore.FindInstanceAsync(client.Reference!, cancellationToken).ConfigureAwait(false);
            if (registration is null)
            {
                logger.LogWarning("Rejected grant request: unknown client instance.");
                return null;
            }

            key = registration.Key;
            instanceId = registration.InstanceId;
            classId = registration.ClassId;
            display = registration.Display;
            registered = true;
        }
        else if (client.Key is { IsReference: true } keyReference)
        {
            key = await clientKeyStore.FindKeyAsync(keyReference.Reference!, cancellationToken).ConfigureAwait(false);
            registered = key is not null;
        }
        else
        {
            key = client.Key;
        }

        if (key is null || key.IsReference || key.Jwk is null || key.Jwk.HasPrivateKey)
        {
            logger.LogWarning("Rejected grant request: the client key is missing, unresolvable or contains private key material.");
            return null;
        }

        string thumbprint;
        try
        {
            thumbprint = key.Jwk.ComputeThumbprint();
        }
        catch (GnapException e)
        {
            logger.LogWarning("Rejected grant request: invalid client JWK ({Reason}).", e.Message);
            return null;
        }

        return new ClientIdentity
        {
            Key = key,
            KeyThumbprint = thumbprint,
            InstanceId = instanceId,
            ClassId = classId,
            Display = display,
            IsRegistered = registered,
        };
    }

    private GnapErrorCode? Validate(GrantRequest request)
    {
        var tokens = request.AccessToken;
        if ((tokens is null || tokens.Count == 0) && request.Subject is null)
        {
            return GnapErrorCode.InvalidRequest;
        }

        if (tokens is not null)
        {
            var labels = new HashSet<string>(StringComparer.Ordinal);
            foreach (var token in tokens)
            {
                if (token.Access is not { Count: > 0 })
                {
                    return GnapErrorCode.InvalidRequest;
                }

                if (tokens.Count > 1 && (string.IsNullOrEmpty(token.Label) || !labels.Add(token.Label)))
                {
                    return GnapErrorCode.InvalidRequest;
                }

                if (token.Flags is { } flags)
                {
                    if (flags.Any(f => f != AccessTokenFlags.Bearer) || flags.Count != flags.Distinct().Count())
                    {
                        return GnapErrorCode.InvalidFlag;
                    }

                    if (token.IsBearer && !_options.AllowBearerTokens)
                    {
                        return GnapErrorCode.InvalidFlag;
                    }
                }
            }
        }

        if (request.Interact is { } interact)
        {
            if (interact.Start is not { Count: > 0 })
            {
                return GnapErrorCode.InvalidRequest;
            }

            if (interact.Finish is { } finish)
            {
                if (!SupportedFinishMethods.Contains(finish.Method)
                    || string.IsNullOrEmpty(finish.Nonce)
                    || !Uri.TryCreate(finish.Uri, UriKind.Absolute, out var callback)
                    || (callback.Scheme != Uri.UriSchemeHttps && callback.Scheme != Uri.UriSchemeHttp)
                    || !string.IsNullOrEmpty(callback.Fragment)
                    || (finish.HashMethod is { } hashMethod && !InteractionFinishHash.IsSupported(hashMethod)))
                {
                    return GnapErrorCode.InvalidRequest;
                }
            }
        }

        return null;
    }

    private async Task<InteractResponse> StartInteractionAsync(HttpContext context, GrantRecord grant, DateTimeOffset now)
    {
        var modes = grant.Request.Interact!.Start!.Select(s => s.Mode).ToHashSet(StringComparer.Ordinal);
        grant.InteractionId = Protocol.NewSecret(16);
        grant.InteractionExpiresAt = now + _options.InteractionLifetime;

        var response = new InteractResponse
        {
            ExpiresIn = (long)_options.InteractionLifetime.TotalSeconds,
        };

        if (modes.Contains(StartModes.Redirect))
        {
            response.Redirect = uris.Interact(context, grant.InteractionId);
        }

        if (modes.Contains(StartModes.UserCode) || modes.Contains(StartModes.UserCodeUri))
        {
            grant.UserCode = await NewUserCodeAsync(context.RequestAborted).ConfigureAwait(false);
            var display = FormatUserCode(grant.UserCode);
            if (modes.Contains(StartModes.UserCode))
            {
                response.UserCode = display;
            }

            if (modes.Contains(StartModes.UserCodeUri))
            {
                response.UserCodeUri = new UserCodeUri { Code = display, Uri = uris.UserCode(context) };
            }
        }

        if (grant.Finish is not null)
        {
            grant.AsNonce = Protocol.NewSecret(16);
            response.Finish = grant.AsNonce;
        }

        return response;
    }

    private async Task<string> NewUserCodeAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var code = string.Create(8, 0, static (span, _) =>
            {
                for (var i = 0; i < span.Length; i++)
                {
                    span[i] = UserCodeAlphabet[System.Security.Cryptography.RandomNumberGenerator.GetInt32(UserCodeAlphabet.Length)];
                }
            });

            if (await grantStore.FindByUserCodeAsync(code, cancellationToken).ConfigureAwait(false) is null)
            {
                return code;
            }
        }
    }

    /// <summary>Formats a normalized user code for display (<c>ABCD-EFGH</c>).</summary>
    public static string FormatUserCode(string code) => code.Length == 8 ? $"{code[..4]}-{code[4..]}" : code;

    /// <summary>Normalizes user input: uppercase letters only, ignoring separators and whitespace.</summary>
    public static string NormalizeUserCode(string? input) =>
        input is null ? string.Empty : new string([.. input.Where(char.IsAsciiLetter).Select(char.ToUpperInvariant)]);
}
