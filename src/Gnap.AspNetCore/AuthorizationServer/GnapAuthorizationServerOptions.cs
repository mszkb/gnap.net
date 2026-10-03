using Microsoft.AspNetCore.Http;

namespace Gnap.AspNetCore.AuthorizationServer;

/// <summary>Configuration of the GNAP authorization server endpoints.</summary>
public sealed class GnapAuthorizationServerOptions
{
    /// <summary>
    /// The name of the <see cref="System.Net.Http.HttpClient"/> (via <c>IHttpClientFactory</c>)
    /// used to deliver <c>push</c> interaction finish messages; configure it, e.g., for proxies.
    /// </summary>
    public const string PushHttpClientName = "Gnap.AspNetCore.FinishPush";

    /// <summary>
    /// The path under which all AS endpoints are mapped. Defaults to <c>/gnap</c>,
    /// giving the grant endpoint <c>/gnap/tx</c>.
    /// </summary>
    public PathString BasePath { get; set; } = "/gnap";

    /// <summary>
    /// The public origin (scheme, host, port and optional path base) used for all
    /// absolute URIs the AS hands out. When unset, it is taken from each request
    /// (configure forwarded headers when running behind a proxy). The grant endpoint
    /// URI derived from it enters the interaction finish hash.
    /// </summary>
    public Uri? PublicOrigin { get; set; }

    /// <summary>The lifetime of issued access tokens. Defaults to 1 hour.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How long interaction modes (redirect URI, user code) stay valid. Defaults to 10 minutes.</summary>
    public TimeSpan InteractionLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// How long the continuation access token of a finalized grant stays valid (for
    /// revoking the grant). Defaults to 1 hour.
    /// </summary>
    public TimeSpan FinalizedGrantLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>The <c>wait</c> (seconds) returned with continuation information. Defaults to 5.</summary>
    public int ContinueWaitSeconds { get; set; } = 5;

    /// <summary>
    /// Whether clients may request bearer tokens (<c>flags: ["bearer"]</c>).
    /// Defaults to <see langword="false"/>: tokens are key-bound unless explicitly allowed.
    /// </summary>
    public bool AllowBearerTokens { get; set; }

    /// <summary>Whether issued tokens offer token management (rotation, revocation). Defaults to <see langword="true"/>.</summary>
    public bool EnableTokenManagement { get; set; } = true;

    /// <summary>Whether token key rotation (RFC 9635 Section 6.1.2) is supported. Defaults to <see langword="true"/>.</summary>
    public bool AllowKeyRotation { get; set; } = true;

    /// <summary>
    /// Whether clients presenting their key by value are assigned an <c>instance_id</c>
    /// (registered in the <see cref="Stores.IClientKeyStore"/>) on their first finalized grant.
    /// Defaults to <see langword="true"/>.
    /// </summary>
    public bool IssueInstanceIds { get; set; } = true;

    /// <summary>Whether the RFC 9767 introspection endpoint is mapped. Defaults to <see langword="true"/>.</summary>
    public bool EnableIntrospection { get; set; } = true;

    /// <summary>
    /// Whether the RFC 9767 resource registration endpoint (<c>{BasePath}/resource</c>)
    /// is mapped, letting registered resource servers obtain access references for
    /// resource sets. Defaults to <see langword="true"/>.
    /// </summary>
    public bool EnableResourceRegistration { get; set; } = true;

    /// <summary>
    /// Whether every request signature must carry a <c>nonce</c> (replay protection,
    /// RFC 9421 Section 7.2.2). Defaults to <see langword="true"/>; nonces are always
    /// checked against the replay store when present.
    /// </summary>
    public bool RequireSignatureNonce { get; set; } = true;

    /// <summary>The maximum accepted age of a request signature. Defaults to 5 minutes.</summary>
    public TimeSpan SignatureMaxAge { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The tolerated clock difference for signature timestamps. Defaults to 5 minutes.</summary>
    public TimeSpan SignatureClockSkew { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The largest accepted request body. Defaults to 64 KiB.</summary>
    public int MaxRequestBodySize { get; set; } = 64 * 1024;

    /// <summary>
    /// The path of the consent UI the browser is sent to once an interaction is bound
    /// to its session (by the default <see cref="Interaction.IGnapInteractionPage"/>);
    /// the interaction identifier is appended as the <c>interaction</c> query parameter.
    /// Defaults to <c>/consent</c>.
    /// </summary>
    public PathString ConsentPath { get; set; } = "/consent";

    /// <summary>The subject identifier formats the AS can release (advertised in discovery).</summary>
    public IList<string> SubjectIdFormatsSupported { get; set; } = [];

    /// <summary>The clock for all timestamps; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}
