using Gnap.Core.Models;

namespace Gnap.Client;

/// <summary>Configuration of a <see cref="GnapClient"/>.</summary>
public sealed class GnapClientOptions
{
    /// <summary>
    /// The AS's grant endpoint URI. It is also the AS identifier that enters the
    /// interaction finish hash (RFC 9635 Section 4.2.3), so configure it exactly as
    /// the AS publishes it.
    /// </summary>
    public Uri? GrantEndpoint { get; set; }

    /// <summary>The client instance's key, used to sign every request to the AS.</summary>
    public GnapClientKey? ClientKey { get; set; }

    /// <summary>
    /// An instance identifier previously assigned by the AS. When set, the
    /// <c>client</c> field is sent by reference (RFC 9635 Section 2.3.1) instead of
    /// carrying the key by value.
    /// </summary>
    public string? InstanceId { get; set; }

    /// <summary>An identifier for the client software (<c>client.class_id</c>).</summary>
    public string? ClassId { get; set; }

    /// <summary>Display information for the RO (<c>client.display</c>).</summary>
    public ClientDisplay? Display { get; set; }

    /// <summary>
    /// The interaction finish hash method to request; <see langword="null"/> uses the
    /// <c>sha-256</c> default without sending <c>hash_method</c>.
    /// </summary>
    public string? FinishHashMethod { get; set; }

    /// <summary>How often a request is retried after an HTTP 5xx or a transport failure. Defaults to 3.</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>The first retry delay; doubled on each further attempt. Defaults to 500 ms.</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(500);

    /// <summary>The upper bound for retry delays, including <c>Retry-After</c>. Defaults to 30 s.</summary>
    public TimeSpan MaxRetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The longest interval between polls after <c>too_fast</c> back-off. Defaults to 60 s.</summary>
    public TimeSpan MaxPollingInterval { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How long a grant is polled before giving up. Defaults to 15 minutes.</summary>
    public TimeSpan MaxPollingDuration { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long discovered AS metadata is cached without a <c>Cache-Control: max-age</c>. Defaults to 1 hour.</summary>
    public TimeSpan MetadataCacheDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>How long before expiry an access token is rotated pre-emptively. Defaults to 30 s.</summary>
    public TimeSpan TokenRefreshSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The clock for signatures, waits, retries and token expiry; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
}
