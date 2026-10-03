using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>
/// The GNAP resource server authentication handler (RFC 9635 Section 7.2): reads
/// <c>Authorization: GNAP &lt;token&gt;</c>, resolves the token through the
/// <see cref="IGnapTokenValidator"/>, rejects expired tokens, and for key-bound tokens
/// requires an <c>httpsig</c> key proof (RFC 9635 Section 7.3.1) by the bound key that
/// covers the <c>Authorization</c> field, with a valid <c>Content-Digest</c> and an
/// unseen nonce. Bearer tokens are accepted only with
/// <see cref="GnapResourceServerOptions.AllowBearerTokens"/>. Failures answer 401 with a
/// <c>WWW-Authenticate: GNAP</c> challenge; failure reasons are logged, never returned.
/// </summary>
public sealed class GnapResourceServerHandler(
    IOptionsMonitor<GnapResourceServerOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IGnapTokenValidator validator,
    GnapResourceServerRuntime runtime)
    : AuthenticationHandler<GnapResourceServerOptions>(options, logger, encoder)
{
    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith(GnapConstants.AuthorizationScheme + " ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        if (!GnapAuthorization.TryParse(header, out var tokenValue))
        {
            return Reject("malformed Authorization field");
        }

        var token = await validator.ValidateAsync(tokenValue, Context.RequestAborted).ConfigureAwait(false);
        if (token is null)
        {
            return Reject("unknown, inactive or revoked token");
        }

        if (token.IsExpired(TimeProvider.GetUtcNow()))
        {
            return Reject("expired token");
        }

        if (token.IsBearer)
        {
            if (!Options.AllowBearerTokens)
            {
                return Reject("bearer tokens are not accepted");
            }
        }
        else if (token.Key is not { } key)
        {
            return Reject("token is neither key-bound nor flagged as bearer");
        }
        else if (await VerifyKeyProofAsync(key).ConfigureAwait(false) is { } failure)
        {
            return Reject(failure);
        }

        Context.Features.Set<IGnapTokenFeature>(new GnapTokenFeature(token));
        var principal = new ClaimsPrincipal(CreateIdentity(token, Scheme.Name));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name));
    }

    /// <inheritdoc />
    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = await runtime.GetChallengeAsync(Options, Logger, Context.RequestAborted).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        // RFC 9635 Section 9.1: the challenge tells the client where (and which access)
        // to request, also when its token lacks the required rights.
        Response.StatusCode = StatusCodes.Status403Forbidden;
        Response.Headers.WWWAuthenticate = await runtime.GetChallengeAsync(Options, Logger, Context.RequestAborted).ConfigureAwait(false);
    }

    private AuthenticateResult Reject(string reason)
    {
        Logger.LogWarning("Rejected GNAP access token on {Method} {Path}: {Reason}", Request.Method, Request.Path, reason);
        return AuthenticateResult.Fail("The access token is not valid for this request.");
    }

    private async Task<string?> VerifyKeyProofAsync(GnapKey key)
    {
        if (key.IsReference || key.Jwk is null || key.Proof?.Method is not ProofMethod.Methods.HttpSig)
        {
            return "the bound key is not an httpsig key by value";
        }

        SignatureAlgorithm algorithm;
        ContentDigestAlgorithm? digest;
        try
        {
            algorithm = key.ToSignatureAlgorithm();
            digest = key.Proof.GetContentDigestAlgorithm();
        }
        catch (GnapException e)
        {
            return $"unusable bound key ({e.Message})";
        }

        var body = await ReadBodyAsync().ConfigureAwait(false);
        if (body is null)
        {
            return "request body exceeds MaxRequestBodySize";
        }

        var proofValidator = new HttpSigKeyProofValidator
        {
            ExpectedKeyId = key.Jwk.Kid,
            RequiredContentDigestAlgorithm = digest,
            NonceStore = runtime.NonceStore,
            RequireNonce = Options.RequireSignatureNonce,
            MaxAge = Options.SignatureMaxAge,
            ClockSkew = Options.SignatureClockSkew,
            TimeProvider = TimeProvider,
        };

        var result = await proofValidator.ValidateAsync(
            new KeyProofContext
            {
                Message = new AspNetCoreRequestContext(Request),
                Key = algorithm,
                Content = body.Length > 0 ? body : null,
            },
            Context.RequestAborted).ConfigureAwait(false);
        return result.Succeeded ? null : $"invalid key proof ({result.FailureReason})";
    }

    /// <summary>Buffers the request body (rewound for the endpoint); <see langword="null"/> when it is too large.</summary>
    private async Task<byte[]?> ReadBodyAsync()
    {
        if (Request.ContentLength is 0)
        {
            return [];
        }

        if (Request.ContentLength > Options.MaxRequestBodySize)
        {
            return null;
        }

        Request.EnableBuffering();
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await Request.Body.ReadAsync(chunk, Context.RequestAborted).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > Options.MaxRequestBodySize)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        Request.Body.Position = 0;
        return buffer.ToArray();
    }

    private static ClaimsIdentity CreateIdentity(GnapTokenInfo token, string scheme)
    {
        var claims = new List<Claim>();
        foreach (var right in token.Access)
        {
            claims.Add(new Claim(GnapClaimTypes.Access, JsonSerializer.Serialize(right, GnapJsonContext.Default.AccessRight), "JSON"));
        }

        if (token.Subject is { } subject)
        {
            claims.Add(new Claim(GnapClaimTypes.Subject, subject));
        }

        if (token.InstanceId is { } instanceId)
        {
            claims.Add(new Claim(GnapClaimTypes.InstanceId, instanceId));
        }

        if (token.Issuer is { } issuer)
        {
            claims.Add(new Claim(GnapClaimTypes.Issuer, issuer));
        }

        return new ClaimsIdentity(claims, scheme, GnapClaimTypes.Subject, null);
    }
}

/// <summary>
/// Shared (singleton) state of the resource server: the nonce replay store for key
/// proofs and the lazily built <c>WWW-Authenticate</c> challenge.
/// </summary>
public sealed class GnapResourceServerRuntime
{
    private readonly IServiceProvider _services;
    private readonly SemaphoreSlim _challengeLock = new(1, 1);
    private string? _challenge;

    /// <summary>Creates the runtime; uses the registered <see cref="INonceStore"/>, if any.</summary>
    public GnapResourceServerRuntime(IServiceProvider services, IOptionsMonitor<GnapResourceServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        _services = services;
        NonceStore = services.GetService<INonceStore>()
            ?? new InMemoryNonceStore(options.Get(GnapResourceServerDefaults.AuthenticationScheme).TimeProvider);
    }

    /// <summary>The replay protection store for request signature nonces.</summary>
    public INonceStore NonceStore { get; }

    /// <summary>
    /// The challenge <c>GNAP as_uri="…", access="…"</c> (RFC 9635 Section 9.1). The grant
    /// endpoint and access reference are discovered/registered once; when that fails the
    /// challenge degrades to what is known and is retried on the next request.
    /// </summary>
    internal async Task<string> GetChallengeAsync(GnapResourceServerOptions options, ILogger logger, CancellationToken cancellationToken)
    {
        if (_challenge is { } cached)
        {
            return cached;
        }

        await _challengeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_challenge is { } raced)
            {
                return raced;
            }

            var complete = true;
            var asClient = _services.GetRequiredService<GnapAsRsClient>();
            var builder = new StringBuilder(GnapConstants.AuthorizationScheme);
            Uri? asUri = options.GrantEndpoint;
            if (asUri is null && options.AuthorizationServer is not null)
            {
                try
                {
                    asUri = await asClient.GetGrantEndpointAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (GnapException e)
                {
                    logger.LogWarning("AS discovery for the challenge failed: {Reason}", e.Message);
                    complete = false;
                }
            }

            var access = options.AccessReference;
            if (access is null && options.ResourceSet is { Count: > 0 } resourceSet)
            {
                try
                {
                    access = await asClient.RegisterResourceSetAsync(resourceSet, cancellationToken).ConfigureAwait(false);
                }
                catch (GnapException e)
                {
                    logger.LogWarning("Resource set registration failed: {Reason}", e.Message);
                    complete = false;
                }
            }

            if (asUri is not null)
            {
                builder.Append(" as_uri=").Append(Quote(asUri.AbsoluteUri));
                if (access is not null)
                {
                    builder.Append(", access=").Append(Quote(access));
                }
            }

            var challenge = builder.ToString();
            if (complete)
            {
                _challenge = challenge;
            }

            return challenge;
        }
        finally
        {
            _challengeLock.Release();
        }
    }

    private static string Quote(string value) => "\"" + value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";
}
