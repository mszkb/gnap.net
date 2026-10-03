using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Authentication;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>Constants of the GNAP resource server.</summary>
public static class GnapResourceServerDefaults
{
    /// <summary>The authentication scheme name (also the HTTP authentication scheme, RFC 9635 Section 7.2).</summary>
    public const string AuthenticationScheme = "GNAP";

    /// <summary>
    /// The name of the <see cref="System.Net.Http.HttpClient"/> (via <c>IHttpClientFactory</c>)
    /// the RS uses to call the AS (discovery, introspection, resource registration).
    /// </summary>
    public const string BackchannelHttpClientName = "Gnap.AspNetCore.ResourceServer";
}

/// <summary>Configuration of the GNAP resource server (token verification middleware).</summary>
public sealed class GnapResourceServerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The AS's origin (issuer). Its RS-facing discovery document
    /// <c>{AuthorizationServer}/.well-known/gnap-as-rs</c> (RFC 9767 Section 3.1) supplies the
    /// grant, introspection and resource registration endpoints not configured explicitly.
    /// </summary>
    public Uri? AuthorizationServer { get; set; }

    /// <summary>
    /// The AS grant endpoint announced to clients as <c>as_uri</c> in the
    /// <c>WWW-Authenticate: GNAP</c> challenge (RFC 9635 Section 9.1). Discovered when unset.
    /// </summary>
    public Uri? GrantEndpoint { get; set; }

    /// <summary>The AS introspection endpoint (RFC 9767 Section 3.3). Discovered when unset.</summary>
    public Uri? IntrospectionEndpoint { get; set; }

    /// <summary>The AS resource registration endpoint (RFC 9767 Section 3.4). Discovered when unset.</summary>
    public Uri? ResourceRegistrationEndpoint { get; set; }

    /// <summary>The identifier this RS is registered under at the AS (sent as <c>resource_server</c>).</summary>
    public string? ResourceServerId { get; set; }

    /// <summary>
    /// This RS's private key (JWK, its <c>kid</c> becoming the signature <c>keyid</c>)
    /// with which every introspection and registration request is signed (<c>httpsig</c>).
    /// </summary>
    public JsonWebKey? SigningKey { get; set; }

    /// <summary>
    /// The access reference announced as <c>access</c> in the challenge, which clients can
    /// request verbatim. When unset and <see cref="ResourceSet"/> is set, the RS registers
    /// that set at the AS on first use and announces the returned reference.
    /// </summary>
    public string? AccessReference { get; set; }

    /// <summary>The rights of access this RS registers at the AS (RFC 9767 Section 3.4) to obtain <see cref="AccessReference"/>.</summary>
    public IList<AccessRight>? ResourceSet { get; set; }

    /// <summary>
    /// Whether bearer tokens (<c>flags: ["bearer"]</c>, no bound key) are accepted.
    /// Defaults to <see langword="false"/>: only key-bound tokens presented with a valid
    /// key proof are accepted.
    /// </summary>
    public bool AllowBearerTokens { get; set; }

    /// <summary>Whether every request signature must carry a <c>nonce</c> (replay protection). Defaults to <see langword="true"/>.</summary>
    public bool RequireSignatureNonce { get; set; } = true;

    /// <summary>The maximum accepted age of a request signature. Defaults to 5 minutes.</summary>
    public TimeSpan SignatureMaxAge { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The tolerated clock difference for signature timestamps. Defaults to 5 minutes.</summary>
    public TimeSpan SignatureClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// The largest request body buffered to verify its <c>Content-Digest</c>; larger
    /// requests with a key-bound token are rejected. Defaults to 1 MiB.
    /// </summary>
    public int MaxRequestBodySize { get; set; } = 1024 * 1024;

    /// <summary>
    /// How long an active introspection result is cached. Entries never outlive the
    /// token's own expiry; revocations at the AS become visible after at most this long
    /// (or immediately via <see cref="GnapIntrospectionCache.Invalidate"/>). Defaults to 1 minute;
    /// <see cref="TimeSpan.Zero"/> disables caching.
    /// </summary>
    public TimeSpan IntrospectionCacheDuration { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>How long an inactive introspection result is cached. Defaults to 10 seconds.</summary>
    public TimeSpan NegativeCacheDuration { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>The maximum number of cached introspection results. Defaults to 10 000.</summary>
    public int IntrospectionCacheSize { get; set; } = 10_000;
}
