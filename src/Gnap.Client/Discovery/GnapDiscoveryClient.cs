using System.Net.Http.Headers;
using System.Text.Json;
using Gnap.Client.Json;
using Gnap.Core;

namespace Gnap.Client.Discovery;

/// <summary>
/// Fetches and caches AS discovery documents: the grant-endpoint form of
/// RFC 9635 Section 9 (HTTP <c>OPTIONS</c> on the grant endpoint) and the
/// well-known form <c>/.well-known/gnap-as-rs</c> (RFC 9767 Section 3.1).
/// Discovery requests are not signed. A <c>Cache-Control: max-age</c> on the
/// response overrides the default cache lifetime.
/// </summary>
public sealed class GnapDiscoveryClient
{
    /// <summary>The well-known path of the AS discovery document.</summary>
    public const string WellKnownPath = "/.well-known/gnap-as-rs";

    private readonly HttpClient _httpClient;
    private readonly GnapMetadataCache _cache;
    private readonly TimeSpan _defaultLifetime;

    /// <summary>Creates a discovery client.</summary>
    /// <param name="httpClient">The HTTP client used for discovery requests.</param>
    /// <param name="cache">The cache to use; a private one when <see langword="null"/>.</param>
    /// <param name="defaultLifetime">The cache lifetime without <c>Cache-Control: max-age</c>; 1 hour when <see langword="null"/>.</param>
    /// <param name="timeProvider">The clock for a private cache.</param>
    public GnapDiscoveryClient(
        HttpClient httpClient,
        GnapMetadataCache? cache = null,
        TimeSpan? defaultLifetime = null,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        _httpClient = httpClient;
        _cache = cache ?? new GnapMetadataCache(timeProvider);
        _defaultLifetime = defaultLifetime ?? TimeSpan.FromHours(1);
    }

    /// <summary>
    /// Discovers the AS via an <c>OPTIONS</c> request to its grant endpoint
    /// (RFC 9635 Section 9), using the cache when possible.
    /// </summary>
    /// <exception cref="GnapClientException">The request failed or the document is malformed.</exception>
    public Task<AuthorizationServerMetadata> GetGrantEndpointMetadataAsync(Uri grantEndpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grantEndpoint);
        return GetAsync(HttpMethod.Options, grantEndpoint, cancellationToken);
    }

    /// <summary>
    /// Discovers the AS via its well-known document <c>{issuer}/.well-known/gnap-as-rs</c>
    /// (RFC 9767 Section 3.1), using the cache when possible.
    /// </summary>
    /// <exception cref="GnapClientException">The request failed or the document is malformed.</exception>
    public Task<AuthorizationServerMetadata> GetWellKnownMetadataAsync(Uri issuer, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        var wellKnown = new UriBuilder(issuer) { Path = WellKnownPath, Query = string.Empty, Fragment = string.Empty }.Uri;
        return GetAsync(HttpMethod.Get, wellKnown, cancellationToken);
    }

    private async Task<AuthorizationServerMetadata> GetAsync(HttpMethod method, Uri uri, CancellationToken cancellationToken)
    {
        if (_cache.TryGet(uri, out var cached))
        {
            return cached;
        }

        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(GnapConstants.MediaType));

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException e)
        {
            throw new GnapClientException($"AS discovery at '{uri}' failed: {e.Message}", e);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new GnapClientException(
                    $"AS discovery at '{uri}' returned HTTP {(int)response.StatusCode}.", response.StatusCode);
            }

            var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            AuthorizationServerMetadata? metadata;
            try
            {
                metadata = JsonSerializer.Deserialize(body, GnapClientJsonContext.Default.AuthorizationServerMetadata);
            }
            catch (JsonException e)
            {
                throw new GnapClientException($"The AS discovery document at '{uri}' is malformed: {e.Message}", e);
            }

            if (metadata?.GrantRequestEndpoint is null)
            {
                throw new GnapClientException($"The AS discovery document at '{uri}' lacks 'grant_request_endpoint'.");
            }

            var lifetime = response.Headers.CacheControl switch
            {
                { NoStore: true } or { NoCache: true } => TimeSpan.Zero,
                { MaxAge: { } maxAge } => maxAge,
                _ => _defaultLifetime,
            };

            if (lifetime > TimeSpan.Zero)
            {
                _cache.Set(uri, metadata, lifetime);
            }

            return metadata;
        }
    }
}
