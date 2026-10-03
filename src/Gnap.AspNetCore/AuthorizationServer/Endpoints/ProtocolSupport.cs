using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;
using Gnap.HttpMessageSignatures.StructuredFields;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>Secrets, hashing and response helpers shared by the AS endpoints.</summary>
internal static class Protocol
{
    /// <summary>A new unguessable value: 256 random bits, base64url.</summary>
    public static string NewSecret(int bytes = 32) => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(bytes));

    /// <summary>The base64url SHA-256 hash of a secret, as kept in the stores.</summary>
    public static string Hash(string secret) => Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    /// <summary>Compares a presented secret with a stored hash in constant time.</summary>
    public static bool MatchesHash(string? presented, string? storedHash) =>
        presented is not null
        && storedHash is not null
        && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(presented)), Encoding.ASCII.GetBytes(storedHash));

    /// <summary>
    /// Fixed, generic error descriptions: the response never says which check failed
    /// (no verification oracle); details go to the log only.
    /// </summary>
    public static string Describe(GnapErrorCode code) => code.Value switch
    {
        "invalid_request" => "The request is malformed or missing a required parameter.",
        "invalid_client" => "The client instance could not be authenticated.",
        "invalid_interaction" => "The interaction reference is incorrect or the interaction has expired.",
        "invalid_flag" => "The requested token flags are not supported.",
        "invalid_rotation" => "The token rotation request is not valid.",
        "key_rotation_not_supported" => "Key rotation is not supported for this access token.",
        "invalid_continuation" => "The continuation request is not valid.",
        "user_denied" => "The resource owner denied the request.",
        "request_denied" => "The request was denied.",
        "unknown_interaction" => "The interaction integrity could not be established.",
        "too_fast" => "The client instance did not respect the wait time.",
        _ => "The request could not be processed.",
    };

    public static int StatusFor(GnapErrorCode code) => code.Value switch
    {
        "invalid_client" or "invalid_continuation" => StatusCodes.Status401Unauthorized,
        "user_denied" or "request_denied" => StatusCodes.Status403Forbidden,
        _ => StatusCodes.Status400BadRequest,
    };

    public static Task WriteErrorAsync(HttpContext context, GnapErrorCode code, int? status = null) =>
        WriteAsync(context, status ?? StatusFor(code), new GrantResponse { Error = new GnapError(code, Describe(code)) });

    public static Task WriteAsync(HttpContext context, int status, GrantResponse response) =>
        WriteJsonAsync(context, status, GnapJson.Serialize(response));

    public static async Task WriteJsonAsync(HttpContext context, int status, string json)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = GnapConstants.MediaType;
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync(json, Encoding.UTF8, context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>Reads the whole body; <see langword="null"/> when it exceeds <paramref name="limit"/>.</summary>
    public static async Task<byte[]?> ReadBodyAsync(HttpContext context, int limit)
    {
        var request = context.Request;
        if (request.ContentLength is { } length && length > limit)
        {
            return null;
        }

        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, context.RequestAborted).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > limit)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }

    /// <summary>The access token from <c>Authorization: GNAP …</c>, if present and well-formed.</summary>
    public static string? GetGnapToken(HttpContext context) =>
        GnapAuthorization.TryParse(context.Request.Headers.Authorization.ToString(), out var token) ? token : null;
}

/// <summary>Builds the absolute URIs the AS hands out.</summary>
internal sealed class GnapEndpointUris(IOptions<GnapAuthorizationServerOptions> options)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public string Origin(HttpContext context)
    {
        if (_options.PublicOrigin is { } origin)
        {
            return origin.AbsoluteUri.TrimEnd('/');
        }

        var request = context.Request;
        return $"{request.Scheme}://{request.Host.ToUriComponent()}{request.PathBase.ToUriComponent()}";
    }

    public string Endpoint(HttpContext context, string relative) =>
        $"{Origin(context)}{_options.BasePath.ToUriComponent()}{relative}";

    public string GrantEndpoint(HttpContext context) => Endpoint(context, GnapPaths.Grant);

    public string Continue(HttpContext context, string grantId) => Endpoint(context, $"{GnapPaths.ContinuePrefix}/{grantId}");

    public string Interact(HttpContext context, string interactionId) => Endpoint(context, $"{GnapPaths.InteractPrefix}/{interactionId}");

    public string UserCode(HttpContext context) => Endpoint(context, GnapPaths.UserCode);

    public string Token(HttpContext context, string manageId) => Endpoint(context, $"{GnapPaths.TokenPrefix}/{manageId}");

    public string Introspection(HttpContext context) => Endpoint(context, GnapPaths.Introspect);
}

/// <summary>The endpoint paths below <see cref="GnapAuthorizationServerOptions.BasePath"/>.</summary>
public static class GnapPaths
{
    /// <summary>The grant endpoint (RFC 9635 Section 2).</summary>
    public const string Grant = "/tx";

    /// <summary>The continuation endpoints, followed by <c>/{grantId}</c> (Section 5).</summary>
    public const string ContinuePrefix = "/continue";

    /// <summary>The interaction redirect start, followed by <c>/{interactionId}</c> (Section 4.1.1).</summary>
    public const string InteractPrefix = "/interact";

    /// <summary>The user code entry page (Sections 4.1.2 and 4.1.3).</summary>
    public const string UserCode = "/device";

    /// <summary>The token management endpoints, followed by <c>/{manageId}</c> (Section 6).</summary>
    public const string TokenPrefix = "/token";

    /// <summary>The token introspection endpoint (RFC 9767 Section 3.3).</summary>
    public const string Introspect = "/introspect";

    /// <summary>The well-known AS discovery document (RFC 9767 Section 3.1), mapped at the application root.</summary>
    public const string WellKnown = "/.well-known/gnap-as-rs";
}

/// <summary>Verifies <c>httpsig</c> key proofs on incoming AS requests with replay protection.</summary>
internal sealed class KeyProofVerifier
{
    private readonly GnapAuthorizationServerOptions _options;
    private readonly INonceStore _nonceStore;
    private readonly ILogger<KeyProofVerifier> _logger;

    public KeyProofVerifier(
        IOptions<GnapAuthorizationServerOptions> options,
        IServiceProvider services,
        ILogger<KeyProofVerifier> logger)
    {
        _options = options.Value;
        _nonceStore = services.GetService<INonceStore>() ?? new InMemoryNonceStore(_options.TimeProvider);
        _logger = logger;
    }

    /// <summary>
    /// Whether the request carries a valid <c>httpsig</c> proof by <paramref name="key"/>
    /// (RFC 9635 Section 7.3.1). Failure reasons are logged, never returned.
    /// </summary>
    public async Task<bool> VerifyAsync(HttpContext context, byte[] body, GnapKey key, string purpose)
    {
        if (key.IsReference || key.Jwk is null || key.Proof?.Method != ProofMethod.Methods.HttpSig)
        {
            _logger.LogWarning("Rejected {Purpose}: the key is not an httpsig key by value.", purpose);
            return false;
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
            _logger.LogWarning("Rejected {Purpose}: unusable key ({Reason}).", purpose, e.Message);
            return false;
        }

        var validator = new HttpSigKeyProofValidator
        {
            ExpectedKeyId = key.Jwk.Kid,
            RequiredContentDigestAlgorithm = digest,
            NonceStore = _nonceStore,
            RequireNonce = _options.RequireSignatureNonce,
            MaxAge = _options.SignatureMaxAge,
            ClockSkew = _options.SignatureClockSkew,
            TimeProvider = _options.TimeProvider,
        };

        var result = await validator.ValidateAsync(
            new KeyProofContext
            {
                Message = new AspNetCoreRequestContext(context.Request),
                Key = algorithm,
                Content = body.Length > 0 ? body : null,
            },
            context.RequestAborted).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            _logger.LogWarning("Rejected {Purpose} {Method} {Path}: {Reason}", purpose, context.Request.Method, context.Request.Path, result.FailureReason);
        }

        return result.Succeeded;
    }

    /// <summary>
    /// Whether some signature of the request covers another signature of the request
    /// (<c>"signature";key="…"</c>), as required for key rotation (RFC 9635 Section 6.1.2).
    /// </summary>
    public static bool HasCoveringSignature(HttpContext context)
    {
        try
        {
            var inputs = SfParser.ParseDictionary(string.Join(", ", context.Request.Headers["Signature-Input"].Where(v => v is not null)));
            var labels = inputs.Select(m => m.Key).ToHashSet(StringComparer.Ordinal);
            return inputs.Any(member =>
                member.Value is SfInnerList list
                && list.Items.Any(item =>
                    item.Value is SfString { Value: "signature" }
                    && item.Parameters.Get("key") is SfString { Value: var covered }
                    && covered != member.Key
                    && labels.Contains(covered)));
        }
        catch (SfParseException)
        {
            return false;
        }
    }
}
