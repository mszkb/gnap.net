using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Gnap.HttpMessageSignatures;

namespace Gnap.Client;

/// <summary>
/// The low-level GNAP client: one method per protocol call of RFC 9635, each
/// sending a single <c>httpsig</c>-signed request (re-signed on every retry) and
/// returning the parsed response. GNAP errors surface as
/// <see cref="GnapProtocolException"/>; HTTP 5xx and transport failures are
/// retried with exponential back-off (honouring <c>Retry-After</c>).
/// Higher-level flow control (interaction, polling, token refresh) lives in
/// <see cref="GnapClient"/>.
/// </summary>
public sealed class GnapProtocolClient
{
    /// <summary>The signature label of the current key in a key rotation request.</summary>
    public const string KeyRotationOldLabel = "sig1";

    /// <summary>The signature label of the new key in a key rotation request.</summary>
    public const string KeyRotationNewLabel = "sig2";

    private readonly HttpClient _httpClient;
    private readonly GnapClientOptions _options;

    /// <summary>Creates the low-level client.</summary>
    public GnapProtocolClient(HttpClient httpClient, GnapClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        _httpClient = httpClient;
        _options = options;
    }

    /// <summary>Sends a grant request (RFC 9635 Section 2) to the grant endpoint.</summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The AS could not be reached or answered unexpectedly.</exception>
    public Task<GrantResponse> RequestGrantAsync(
        Uri grantEndpoint,
        GrantRequest request,
        GnapClientKey key,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grantEndpoint);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(key);
        var body = Encoding.UTF8.GetBytes(GnapJson.Serialize(request));
        return SendAsync(HttpMethod.Post, grantEndpoint, accessToken: null, body, key, cancellationToken);
    }

    /// <summary>
    /// Continues a grant (RFC 9635 Section 5): with an <paramref name="interactRef"/>
    /// after a finished interaction (Section 5.1), or without content as a poll
    /// (Section 5.2). The caller is responsible for respecting <c>wait</c>.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The AS could not be reached or answered unexpectedly.</exception>
    public Task<GrantResponse> ContinueGrantAsync(
        ContinueResponse continuation,
        string? interactRef,
        GnapClientKey key,
        CancellationToken cancellationToken = default)
    {
        var (uri, token) = RequireContinuation(continuation);
        ArgumentNullException.ThrowIfNull(key);
        var body = interactRef is null
            ? null
            : Encoding.UTF8.GetBytes(GnapJson.Serialize(new ContinueRequest { InteractRef = interactRef }));
        return SendAsync(HttpMethod.Post, uri, token, body, key, cancellationToken);
    }

    /// <summary>Modifies a grant with a <c>PATCH</c> to the continuation URI (RFC 9635 Section 5.3).</summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The AS could not be reached or answered unexpectedly.</exception>
    public Task<GrantResponse> UpdateGrantAsync(
        ContinueResponse continuation,
        GrantRequest modification,
        GnapClientKey key,
        CancellationToken cancellationToken = default)
    {
        var (uri, token) = RequireContinuation(continuation);
        ArgumentNullException.ThrowIfNull(modification);
        ArgumentNullException.ThrowIfNull(key);
        var body = Encoding.UTF8.GetBytes(GnapJson.Serialize(modification));
        return SendAsync(HttpMethod.Patch, uri, token, body, key, cancellationToken);
    }

    /// <summary>Revokes a grant with a <c>DELETE</c> to the continuation URI (RFC 9635 Section 5.4).</summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The AS could not be reached or answered unexpectedly.</exception>
    public async Task CancelGrantAsync(ContinueResponse continuation, GnapClientKey key, CancellationToken cancellationToken = default)
    {
        var (uri, token) = RequireContinuation(continuation);
        ArgumentNullException.ThrowIfNull(key);
        await SendAsync(HttpMethod.Delete, uri, token, body: null, key, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rotates an access token (RFC 9635 Section 6.1) with a <c>POST</c> to its
    /// management URI, signed with the key the token is bound to.
    /// </summary>
    /// <returns>The new access token. The old value must no longer be used.</returns>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error, e.g. <c>invalid_rotation</c>.</exception>
    /// <exception cref="GnapClientException">The token has no management URI or the AS answered unexpectedly.</exception>
    public async Task<AccessTokenResponse> RotateTokenAsync(
        AccessTokenResponse token,
        GnapClientKey key,
        CancellationToken cancellationToken = default)
    {
        var (uri, manageToken) = RequireManagement(token);
        ArgumentNullException.ThrowIfNull(key);
        var response = await SendAsync(HttpMethod.Post, uri, manageToken, body: null, key, cancellationToken).ConfigureAwait(false);
        return SingleToken(response);
    }

    /// <summary>
    /// Rotates the key bound to an access token (RFC 9635 Section 6.1.2): the
    /// request carries the new key and is signed by both keys, the new key's
    /// signature covering the old one.
    /// </summary>
    /// <returns>The access token now bound to <paramref name="newKey"/>.</returns>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error, e.g. <c>key_rotation_not_supported</c>.</exception>
    /// <exception cref="GnapClientException">The token has no management URI or the AS answered unexpectedly.</exception>
    public async Task<AccessTokenResponse> RotateTokenKeyAsync(
        AccessTokenResponse token,
        GnapClientKey currentKey,
        GnapClientKey newKey,
        CancellationToken cancellationToken = default)
    {
        var (uri, manageToken) = RequireManagement(token);
        ArgumentNullException.ThrowIfNull(currentKey);
        ArgumentNullException.ThrowIfNull(newKey);
        if (newKey.PresentedKey.IsReference)
        {
            throw new ArgumentException("Key rotation requires the new key by value.", nameof(newKey));
        }

        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WritePropertyName("key");
            JsonSerializer.Serialize(writer, newKey.PresentedKey, GnapJsonContext.Default.GnapKey);
            writer.WriteEndObject();
        }

        var body = buffer.ToArray();
        var response = await SendAsync(
            HttpMethod.Post,
            uri,
            manageToken,
            body,
            currentKey,
            cancellationToken,
            async request =>
            {
                // Section 6.1.2: prove possession of both keys; the new key's signature
                // covers the old key's signature so the two cannot be separated.
                await newKey.CreateProofer(
                        _options.TimeProvider,
                        KeyRotationNewLabel,
                        [
                            SignatureComponent.Field("signature").WithKey(KeyRotationOldLabel),
                            SignatureComponent.Field("signature-input").WithKey(KeyRotationOldLabel),
                        ])
                    .AddProofAsync(request, cancellationToken)
                    .ConfigureAwait(false);
            }).ConfigureAwait(false);
        return SingleToken(response);
    }

    /// <summary>Revokes an access token with a <c>DELETE</c> to its management URI (RFC 9635 Section 6.2).</summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The token has no management URI or the AS answered unexpectedly.</exception>
    public async Task RevokeTokenAsync(AccessTokenResponse token, GnapClientKey key, CancellationToken cancellationToken = default)
    {
        var (uri, manageToken) = RequireManagement(token);
        ArgumentNullException.ThrowIfNull(key);
        await SendAsync(HttpMethod.Delete, uri, manageToken, body: null, key, cancellationToken).ConfigureAwait(false);
    }

    private async Task<GrantResponse> SendAsync(
        HttpMethod method,
        Uri uri,
        string? accessToken,
        byte[]? body,
        GnapClientKey key,
        CancellationToken cancellationToken,
        Func<HttpRequestMessage, Task>? additionalProof = null)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(GnapConstants.MediaType));
            if (body is not null)
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue(GnapConstants.MediaType);
            }

            if (accessToken is not null)
            {
                GnapAuthorization.Apply(request, accessToken);
            }

            // Every attempt carries a fresh signature (new created/nonce), so
            // replay protection at the AS never rejects a retry.
            var label = additionalProof is null ? "sig1" : KeyRotationOldLabel;
            await key.CreateProofer(_options.TimeProvider, label).AddProofAsync(request, cancellationToken).ConfigureAwait(false);
            if (additionalProof is not null)
            {
                await additionalProof(request).ConfigureAwait(false);
            }

            HttpResponseMessage response;
            try
            {
                response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException) when (attempt < _options.MaxRetries)
            {
                await DelayAsync(RetryDelay(attempt, retryAfter: null), cancellationToken).ConfigureAwait(false);
                continue;
            }
            catch (HttpRequestException e)
            {
                throw new GnapClientException($"The request to '{uri}' failed: {e.Message}", e);
            }

            using (response)
            {
                if ((int)response.StatusCode >= 500 && attempt < _options.MaxRetries)
                {
                    await DelayAsync(RetryDelay(attempt, response.Headers.RetryAfter), cancellationToken).ConfigureAwait(false);
                    continue;
                }

                return await ParseResponseAsync(uri, response, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async Task<GrantResponse> ParseResponseAsync(Uri uri, HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var content = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        GrantResponse? parsed = null;
        if (content.Length > 0)
        {
            try
            {
                parsed = JsonSerializer.Deserialize(content, GnapJsonContext.Default.GrantResponse);
            }
            catch (JsonException e) when (response.IsSuccessStatusCode)
            {
                throw new GnapClientException($"The response from '{uri}' is not a valid GNAP message: {e.Message}", e);
            }
            catch (JsonException)
            {
                // A non-JSON error page; reported by status below.
            }
        }

        if (parsed?.Error is not null)
        {
            throw new GnapProtocolException(parsed, response.StatusCode);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new GnapClientException(
                $"The request to '{uri}' failed with HTTP {(int)response.StatusCode} and no GNAP error.",
                response.StatusCode);
        }

        return parsed ?? new GrantResponse();
    }

    private TimeSpan RetryDelay(int attempt, RetryConditionHeaderValue? retryAfter)
    {
        var delay = retryAfter switch
        {
            { Delta: { } delta } => delta,
            { Date: { } date } => date - _options.TimeProvider.GetUtcNow(),
            _ => _options.RetryBaseDelay * Math.Pow(2, attempt),
        };

        if (delay < TimeSpan.Zero)
        {
            delay = TimeSpan.Zero;
        }

        return delay > _options.MaxRetryDelay ? _options.MaxRetryDelay : delay;
    }

    private Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        delay <= TimeSpan.Zero
            ? Task.CompletedTask
            : Task.Delay(delay, _options.TimeProvider, cancellationToken);

    private static (Uri Uri, string Token) RequireContinuation(ContinueResponse continuation)
    {
        ArgumentNullException.ThrowIfNull(continuation);
        if (!Uri.TryCreate(continuation.Uri, UriKind.Absolute, out var uri) || continuation.AccessToken?.Value is not { } token)
        {
            throw new GnapClientException("The continuation response lacks an absolute 'uri' or an 'access_token'.");
        }

        return (uri, token);
    }

    private static (Uri Uri, string Token) RequireManagement(AccessTokenResponse token)
    {
        ArgumentNullException.ThrowIfNull(token);
        if (token.Manage is not { } manage
            || !Uri.TryCreate(manage.Uri, UriKind.Absolute, out var uri)
            || manage.AccessToken?.Value is not { } manageToken)
        {
            throw new GnapClientException("The access token offers no token management (missing 'manage.uri' or 'manage.access_token').");
        }

        return (uri, manageToken);
    }

    private static AccessTokenResponse SingleToken(GrantResponse response) =>
        response.AccessToken is [{ Value: not null } token]
            ? token
            : throw new GnapClientException("The token management response does not contain exactly one access token.");
}
