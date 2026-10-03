using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.HttpMessageSignatures.AspNetCore;

/// <summary>Settings for the signature verification middleware.</summary>
public sealed class HttpMessageSignatureOptions
{
    /// <summary>The resolver mapping <c>keyid</c>/<c>alg</c> to key material. Required.</summary>
    public IVerificationKeyResolver? KeyResolver { get; set; }

    /// <summary>Components every accepted signature must cover.</summary>
    public IReadOnlyCollection<SignatureComponent> RequiredComponents { get; set; } =
        [SignatureComponent.Method, SignatureComponent.TargetUri];

    /// <summary>Tolerated clock difference for timestamp checks. Defaults to 5 minutes.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>If set, signatures older than this are rejected.</summary>
    public TimeSpan? MaxAge { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Whether a request with a body must carry a valid <c>Content-Digest</c> field.
    /// The body is buffered up to <see cref="MaxBufferedContentLength"/> to check it,
    /// and only after the signature itself has been verified.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool RequireContentDigestForBodies { get; set; } = true;

    /// <summary>
    /// The largest body buffered for digest validation. Defaults to 1 MiB. The
    /// limit is enforced while reading, so it also applies to bodies without a
    /// <c>Content-Length</c> (e.g. <c>Transfer-Encoding: chunked</c>, HTTP/2);
    /// larger bodies are rejected with 401.
    /// </summary>
    public long MaxBufferedContentLength { get; set; } = 1024 * 1024;

    /// <summary>Paths (exact prefix match) excluded from signature verification.</summary>
    public IReadOnlyCollection<PathString> ExcludedPaths { get; set; } = [];

    /// <summary>The clock used for timestamp checks; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}

/// <summary>Exposes the verification outcome of the current request to endpoints.</summary>
public interface IHttpMessageSignatureFeature
{
    /// <summary>The successful verification result, including the parsed signature parameters.</summary>
    VerificationResult Result { get; }
}

/// <summary>
/// ASP.NET Core middleware that rejects requests without a valid HTTP message
/// signature (RFC 9421) and, for requests with content, without a valid
/// <c>Content-Digest</c> (RFC 9530).
/// </summary>
public sealed class HttpMessageSignatureMiddleware
{
    private readonly RequestDelegate _next;
    private readonly HttpMessageSignatureOptions _options;
    private readonly HttpMessageVerifier _verifier;
    private readonly ILogger<HttpMessageSignatureMiddleware> _logger;

    /// <summary>Creates the middleware; wired up by <c>UseHttpMessageSignatureVerification</c>.</summary>
    public HttpMessageSignatureMiddleware(
        RequestDelegate next,
        IOptions<HttpMessageSignatureOptions> options,
        ILogger<HttpMessageSignatureMiddleware> logger)
    {
        _next = next;
        _options = options.Value;
        _logger = logger;
        var keyResolver = _options.KeyResolver
            ?? throw new InvalidOperationException("HttpMessageSignatureOptions.KeyResolver must be configured.");
        _verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = keyResolver,
            ClockSkew = _options.ClockSkew,
            MaxAge = _options.MaxAge,
            RequiredComponents = _options.RequiredComponents,
            TimeProvider = _options.TimeProvider,
        });
    }

    /// <summary>Verifies the request, then either continues the pipeline or responds 401.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        foreach (var excluded in _options.ExcludedPaths)
        {
            if (context.Request.Path.StartsWithSegments(excluded))
            {
                await _next(context).ConfigureAwait(false);
                return;
            }
        }

        // Verify the signature first: it covers only header fields (including
        // Content-Digest, if present), so no body bytes are read on behalf of a
        // request that is not authenticated.
        var result = await _verifier
            .VerifyAsync(new AspNetCoreRequestContext(context.Request), cancellationToken: context.RequestAborted)
            .ConfigureAwait(false);

        if (!result.Succeeded)
        {
            await RejectAsync(context, result.FailureReason ?? "signature verification failed").ConfigureAwait(false);
            return;
        }

        var digestFailure = await ValidateContentDigestAsync(context).ConfigureAwait(false);
        if (digestFailure is not null)
        {
            await RejectAsync(context, digestFailure).ConfigureAwait(false);
            return;
        }

        context.Features.Set<IHttpMessageSignatureFeature>(new SignatureFeature(result));
        await _next(context).ConfigureAwait(false);
    }

    private async Task<string?> ValidateContentDigestAsync(HttpContext context)
    {
        var request = context.Request;
        var hasBody = context.Features.Get<IHttpRequestBodyDetectionFeature>()?.CanHaveBody
            ?? (request.ContentLength is > 0 || request.Headers.TransferEncoding.Count > 0);
        if (request.ContentLength == 0)
        {
            hasBody = false;
        }

        var digestHeader = request.Headers["Content-Digest"];

        if (!hasBody && digestHeader.Count == 0)
        {
            return null;
        }

        if (hasBody && digestHeader.Count == 0)
        {
            return _options.RequireContentDigestForBodies
                ? "the request has a body but no Content-Digest field"
                : null;
        }

        var limit = Math.Max(0, _options.MaxBufferedContentLength);
        if (request.ContentLength is { } length && length > limit)
        {
            return "the request body exceeds the digest validation buffer limit";
        }

        // Without a Content-Length (chunked, HTTP/2) the size is unknown up front;
        // ValidateAsync counts while hashing and stops one byte past the limit, so
        // at most limit + 1 bytes are ever buffered.
        request.EnableBuffering(bufferThreshold: (int)Math.Min(limit, int.MaxValue));
        var validation = await ContentDigest
            .ValidateAsync(string.Join(", ", digestHeader.Where(v => v is not null)), request.Body, limit, context.RequestAborted)
            .ConfigureAwait(false);
        request.Body.Position = 0;

        return validation switch
        {
            ContentDigestValidation.Valid => null,
            ContentDigestValidation.ContentTooLarge => "the request body exceeds the digest validation buffer limit",
            ContentDigestValidation.Mismatch => "the Content-Digest does not match the request body",
            ContentDigestValidation.NoSupportedAlgorithm => "the Content-Digest uses no supported algorithm",
            _ => "the Content-Digest field is malformed",
        };
    }

    private async Task RejectAsync(HttpContext context, string reason)
    {
        // The precise reason is logged for operators but not echoed to the client,
        // to avoid giving attackers a verification oracle.
        _logger.LogWarning("Rejected request {Method} {Path}: {Reason}", context.Request.Method, context.Request.Path, reason);
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Signature";
        await context.Response.WriteAsync("Invalid or missing HTTP message signature.", context.RequestAborted).ConfigureAwait(false);
    }

    private sealed class SignatureFeature(VerificationResult result) : IHttpMessageSignatureFeature
    {
        public VerificationResult Result { get; } = result;
    }
}

/// <summary>Registration helpers for the signature verification middleware.</summary>
public static class HttpMessageSignatureExtensions
{
    /// <summary>Registers and configures the verification options.</summary>
    public static IServiceCollection AddHttpMessageSignatureVerification(
        this IServiceCollection services,
        Action<HttpMessageSignatureOptions> configure)
    {
        services.Configure(configure);
        return services;
    }

    /// <summary>Adds the verification middleware to the pipeline.</summary>
    public static IApplicationBuilder UseHttpMessageSignatureVerification(this IApplicationBuilder app) =>
        app.UseMiddleware<HttpMessageSignatureMiddleware>();
}
