using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>
/// The continuation endpoints (RFC 9635 Section 5) at <c>{BasePath}/continue/{grantId}</c>:
/// <c>POST</c> continues after interaction or polls, <c>DELETE</c> revokes the grant,
/// <c>PATCH</c> (grant modification) is answered with <c>invalid_request</c>.
/// </summary>
internal sealed class ContinuationEndpoint(
    IGrantStore grantStore,
    ITokenStore tokenStore,
    GrantIssuer issuer,
    KeyProofVerifier proofVerifier,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<ContinuationEndpoint> logger)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    private DateTimeOffset Now => _options.TimeProvider.GetUtcNow();

    public async Task ContinueAsync(HttpContext context)
    {
        var (grant, body) = await AuthenticateAsync(context).ConfigureAwait(false);
        if (grant is null)
        {
            return;
        }

        if (grant.State == GrantState.Revoked)
        {
            // A denial is reported exactly once; afterwards the grant is gone for the client.
            var code = grant.DenialCode is { } denial && !grant.DenialReported ? new GnapErrorCode(denial) : GnapErrorCode.InvalidContinuation;
            grant.DenialReported = true;
            grant.ContinuationTokenHash = null;
            await grantStore.TryUpdateAsync(grant, context.RequestAborted).ConfigureAwait(false);
            await Protocol.WriteErrorAsync(context, code).ConfigureAwait(false);
            return;
        }

        string? interactRef = null;
        if (body!.Length > 0)
        {
            try
            {
                interactRef = JsonSerializer.Deserialize(body, GnapJsonContext.Default.ContinueRequest)?.InteractRef;
            }
            catch (JsonException)
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
                return;
            }

            if (string.IsNullOrEmpty(interactRef))
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
                return;
            }
        }

        if (interactRef is not null)
        {
            // One-time use (RFC 9635 Section 5.1): a reference that was already used
            // cannot establish the integrity of this interaction again.
            if (Protocol.MatchesHash(interactRef, grant.ConsumedInteractRefHash))
            {
                logger.LogWarning("Rejected continuation of grant {GrantId}: interaction reference reused.", grant.Id);
                await Protocol.WriteErrorAsync(context, GnapErrorCode.UnknownInteraction).ConfigureAwait(false);
                return;
            }

            // A wrong reference leaves the grant untouched.
            if (!Protocol.MatchesHash(interactRef, grant.InteractRefHash))
            {
                logger.LogWarning("Rejected continuation of grant {GrantId}: interaction reference mismatch.", grant.Id);
                await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidInteraction).ConfigureAwait(false);
                return;
            }

            grant.ConsumedInteractRefHash = grant.InteractRefHash;
            grant.InteractRefHash = null;
        }
        else
        {
            if (grant.State == GrantState.Finalized)
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
                return;
            }

            if (grant.NotBefore is { } notBefore && Now < notBefore)
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.TooFast).ConfigureAwait(false);
                return;
            }
        }

        GrantResponse response;
        IReadOnlyList<string> issued = [];
        if (grant.State == GrantState.Approved && (interactRef is not null || grant.Finish is null))
        {
            (response, issued) = await issuer.FinalizeAsync(context, grant).ConfigureAwait(false);
        }
        else if (grant.State is GrantState.Pending or GrantState.Approved)
        {
            // Still waiting: for the RO's decision, or (with a finish method) for the
            // interaction reference. The continuation token rotates on every call.
            response = new GrantResponse
            {
                Continue = issuer.RotateContinuation(context, grant, grant.ContinuationExpiresAt ?? Now),
            };
        }
        else
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
            return;
        }

        if (!await grantStore.TryUpdateAsync(grant, context.RequestAborted).ConfigureAwait(false))
        {
            // Lost a race with a concurrent continuation: undo what this call issued.
            foreach (var tokenId in issued)
            {
                await tokenStore.RevokeAsync(tokenId, context.RequestAborted).ConfigureAwait(false);
            }

            logger.LogWarning("Rejected continuation of grant {GrantId}: concurrent modification.", grant.Id);
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
            return;
        }

        await Protocol.WriteAsync(context, StatusCodes.Status200OK, response).ConfigureAwait(false);
    }

    public async Task RevokeAsync(HttpContext context)
    {
        var (grant, _) = await AuthenticateAsync(context).ConfigureAwait(false);
        if (grant is null)
        {
            return;
        }

        if (!GrantStateMachine.CanTransition(grant.State, GrantState.Revoked))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
            return;
        }

        grant.TransitionTo(GrantState.Revoked);
        grant.ContinuationTokenHash = null;
        grant.InteractRefHash = null;
        grant.DenialReported = true;
        if (!await grantStore.TryUpdateAsync(grant, context.RequestAborted).ConfigureAwait(false))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
            return;
        }

        await tokenStore.RevokeByGrantAsync(grant.Id, context.RequestAborted).ConfigureAwait(false);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    public async Task ModifyAsync(HttpContext context)
    {
        var (grant, _) = await AuthenticateAsync(context).ConfigureAwait(false);
        if (grant is not null)
        {
            // Grant modification (RFC 9635 Section 5.3) is optional and not supported.
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Authenticates a continuation call: the continuation access token must be the
    /// grant's current one and the request must be signed by the grant's client key.
    /// Writes the error response and returns <see langword="null"/> on failure.
    /// </summary>
    private async Task<(GrantRecord? Grant, byte[]? Body)> AuthenticateAsync(HttpContext context)
    {
        var grantId = context.Request.RouteValues["grantId"] as string;
        var token = Protocol.GetGnapToken(context);
        var grant = grantId is null ? null : await grantStore.FindAsync(grantId, context.RequestAborted).ConfigureAwait(false);

        // Unknown grant, missing/foreign/rotated token and expiry are indistinguishable to the caller.
        if (grant is null
            || !Protocol.MatchesHash(token, grant.ContinuationTokenHash)
            || (grant.ContinuationExpiresAt is { } expiresAt && Now >= expiresAt))
        {
            logger.LogWarning("Rejected continuation: unknown grant or invalid/expired continuation token.");
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidContinuation).ConfigureAwait(false);
            return (null, null);
        }

        var body = await Protocol.ReadBodyAsync(context, _options.MaxRequestBodySize).ConfigureAwait(false);
        if (body is null)
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return (null, null);
        }

        // Key binding: only the client instance that started the grant may continue it.
        if (!await proofVerifier.VerifyAsync(context, body, grant.ClientKey, "continuation").ConfigureAwait(false))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidClient).ConfigureAwait(false);
            return (null, null);
        }

        return (grant, body);
    }
}
