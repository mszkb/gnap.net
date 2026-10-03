using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Gnap.Core.Proofing;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>The RS-facing discovery document of an AS (RFC 9767 Section 3.1).</summary>
public sealed class GnapAsRsMetadata
{
    /// <summary>The grant endpoint (<c>grant_request_endpoint</c>).</summary>
    public Uri? GrantRequestEndpoint { get; init; }

    /// <summary>The introspection endpoint (<c>introspection_endpoint</c>).</summary>
    public Uri? IntrospectionEndpoint { get; init; }

    /// <summary>The resource registration endpoint (<c>resource_registration_endpoint</c>).</summary>
    public Uri? ResourceRegistrationEndpoint { get; init; }

    /// <summary>The token formats the AS issues (<c>token_formats_supported</c>).</summary>
    public IReadOnlyList<string> TokenFormatsSupported { get; init; } = [];

    /// <summary>The key proofing methods the AS supports (<c>key_proofs_supported</c>).</summary>
    public IReadOnlyList<string> KeyProofsSupported { get; init; } = [];
}

/// <summary>
/// The RS's connection to its AS (RFC 9767): discovery via
/// <c>/.well-known/gnap-as-rs</c>, resource set registration and token introspection.
/// Every registration and introspection request is signed (<c>httpsig</c>) with the
/// RS's <see cref="GnapResourceServerOptions.SigningKey"/> and names the RS by its
/// <see cref="GnapResourceServerOptions.ResourceServerId"/>.
/// </summary>
public sealed class GnapAsRsClient
{
    /// <summary>The well-known path of the RS-facing AS discovery document.</summary>
    public const string WellKnownPath = "/.well-known/gnap-as-rs";

    private readonly HttpClient _http;
    private readonly GnapResourceServerOptions _options;
    private readonly SemaphoreSlim _metadataLock = new(1, 1);
    private GnapAsRsMetadata? _metadata;

    /// <summary>Creates the client.</summary>
    public GnapAsRsClient(HttpClient httpClient, GnapResourceServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        _http = httpClient;
        _options = options;
    }

    /// <summary>
    /// Fetches (once, then cached) the AS's RS-facing discovery document from
    /// <see cref="GnapResourceServerOptions.AuthorizationServer"/>.
    /// </summary>
    /// <exception cref="GnapException">No AS is configured or the document cannot be retrieved.</exception>
    public async Task<GnapAsRsMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
    {
        if (_metadata is { } cached)
        {
            return cached;
        }

        var issuer = _options.AuthorizationServer
            ?? throw new GnapException("No AuthorizationServer is configured for discovery.");
        await _metadataLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_metadata is { } raced)
            {
                return raced;
            }

            var uri = new Uri(issuer.AbsoluteUri.TrimEnd('/') + WellKnownPath);
            using var response = await SendAsync(new HttpRequestMessage(HttpMethod.Get, uri), sign: false, cancellationToken).ConfigureAwait(false);
            using var document = await ReadJsonAsync(response, "discovery", cancellationToken).ConfigureAwait(false);
            var root = document.RootElement;
            _metadata = new GnapAsRsMetadata
            {
                GrantRequestEndpoint = ReadUri(root, "grant_request_endpoint"),
                IntrospectionEndpoint = ReadUri(root, "introspection_endpoint"),
                ResourceRegistrationEndpoint = ReadUri(root, "resource_registration_endpoint"),
                TokenFormatsSupported = ReadStrings(root, "token_formats_supported"),
                KeyProofsSupported = ReadStrings(root, "key_proofs_supported"),
            };
            return _metadata;
        }
        finally
        {
            _metadataLock.Release();
        }
    }

    /// <summary>The AS grant endpoint: configured, or discovered.</summary>
    public async Task<Uri> GetGrantEndpointAsync(CancellationToken cancellationToken = default) =>
        _options.GrantEndpoint
        ?? (await GetMetadataAsync(cancellationToken).ConfigureAwait(false)).GrantRequestEndpoint
        ?? throw new GnapException("The AS does not advertise a grant endpoint.");

    /// <summary>
    /// Registers a set of resources at the AS (RFC 9767 Section 3.4).
    /// </summary>
    /// <returns>The <c>resource_reference</c> clients can request in place of <paramref name="access"/>.</returns>
    /// <exception cref="GnapException">The AS refused the registration or answered unexpectedly.</exception>
    public async Task<string> RegisterResourceSetAsync(IList<AccessRight> access, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        var endpoint = _options.ResourceRegistrationEndpoint
            ?? (await GetMetadataAsync(cancellationToken).ConfigureAwait(false)).ResourceRegistrationEndpoint
            ?? throw new GnapException("The AS does not advertise a resource registration endpoint.");

        var body = WriteJson(writer =>
        {
            writer.WritePropertyName("access");
            JsonSerializer.Serialize(writer, access, GnapJsonContext.Default.IListAccessRight);
            writer.WriteString("resource_server", RequireResourceServerId());
        });

        using var response = await PostSignedAsync(endpoint, body, cancellationToken).ConfigureAwait(false);
        using var document = await ReadJsonAsync(response, "resource registration", cancellationToken).ConfigureAwait(false);
        return document.RootElement.TryGetProperty("resource_reference", out var reference) && reference.ValueKind == JsonValueKind.String
            ? reference.GetString()!
            : throw new GnapException("The AS returned no resource_reference.");
    }

    /// <summary>
    /// Introspects an access token (RFC 9767 Section 3.3).
    /// </summary>
    /// <param name="accessToken">The token value as presented by the client.</param>
    /// <param name="access">Optional rights the token must cover; the AS reports it inactive otherwise.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    /// <returns>The token description, or <see langword="null"/> when the AS reports it inactive.</returns>
    /// <exception cref="GnapException">The AS refused the request or answered unexpectedly.</exception>
    public async Task<GnapTokenInfo?> IntrospectAsync(string accessToken, IList<AccessRight>? access = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        var endpoint = _options.IntrospectionEndpoint
            ?? (await GetMetadataAsync(cancellationToken).ConfigureAwait(false)).IntrospectionEndpoint
            ?? throw new GnapException("The AS does not advertise an introspection endpoint.");

        var body = WriteJson(writer =>
        {
            writer.WriteString("access_token", accessToken);
            writer.WriteString("resource_server", RequireResourceServerId());
            if (access is not null)
            {
                writer.WritePropertyName("access");
                JsonSerializer.Serialize(writer, access, GnapJsonContext.Default.IListAccessRight);
            }
        });

        using var response = await PostSignedAsync(endpoint, body, cancellationToken).ConfigureAwait(false);
        using var document = await ReadJsonAsync(response, "introspection", cancellationToken).ConfigureAwait(false);
        return GnapTokenInfo.Parse(document.RootElement, requireActive: true);
    }

    private string RequireResourceServerId() =>
        _options.ResourceServerId ?? throw new GnapException("No ResourceServerId is configured.");

    private async Task<HttpResponseMessage> PostSignedAsync(Uri endpoint, byte[] body, CancellationToken cancellationToken)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, endpoint) { Content = new ByteArrayContent(body) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(GnapConstants.MediaType);
        return await SendAsync(request, sign: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, bool sign, CancellationToken cancellationToken)
    {
        using (request)
        {
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(GnapConstants.MediaType));
            if (sign)
            {
                var key = _options.SigningKey ?? throw new GnapException("No SigningKey is configured for the resource server.");
                var proofer = new HttpSigKeyProofer(key.ToSignatureAlgorithm(), key.Kid)
                {
                    TimeProvider = _options.TimeProvider ?? TimeProvider.System,
                };
                await proofer.AddProofAsync(request, cancellationToken).ConfigureAwait(false);
            }

            try
            {
                return await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException e)
            {
                throw new GnapException($"The AS could not be reached: {e.Message}", e);
            }
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response, string operation, CancellationToken cancellationToken)
    {
        if (!response.IsSuccessStatusCode)
        {
            throw new GnapException($"The AS rejected the {operation} request with HTTP {(int)response.StatusCode}.");
        }

        try
        {
            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                return await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            }
        }
        catch (JsonException e)
        {
            throw new GnapException($"The AS returned a malformed {operation} response.", e);
        }
    }

    private static byte[] WriteJson(Action<Utf8JsonWriter> writeMembers)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writeMembers(writer);
            writer.WriteEndObject();
        }

        return buffer.ToArray();
    }

    private static Uri? ReadUri(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
        && Uri.TryCreate(value.GetString(), UriKind.Absolute, out var uri)
            ? uri
            : null;

    private static string[] ReadStrings(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray()
            : [];
}
