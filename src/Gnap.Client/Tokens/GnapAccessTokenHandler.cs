using System.Net;

namespace Gnap.Client.Tokens;

/// <summary>
/// An <see cref="HttpClient"/> handler that presents a GNAP access token on
/// every RS request (RFC 9635 Section 7.2, with an <c>httpsig</c> key proof for
/// bound tokens). Expiring tokens are rotated before use; when the RS answers
/// 401 the token is rotated once and the request is re-sent with a fresh
/// signature.
/// </summary>
public sealed class GnapAccessTokenHandler : DelegatingHandler
{
    private readonly GnapTokenSource _tokenSource;

    /// <summary>Creates the handler; set <see cref="DelegatingHandler.InnerHandler"/> or use it in an HTTP client pipeline.</summary>
    public GnapAccessTokenHandler(GnapTokenSource tokenSource)
    {
        ArgumentNullException.ThrowIfNull(tokenSource);
        _tokenSource = tokenSource;
    }

    /// <summary>Creates the handler with an inner handler.</summary>
    public GnapAccessTokenHandler(GnapTokenSource tokenSource, HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
        ArgumentNullException.ThrowIfNull(tokenSource);
        _tokenSource = tokenSource;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Buffer the content once so a retry can re-send (and re-sign) it.
        byte[]? content = null;
        if (request.Content is not null)
        {
            content = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        }

        var token = await _tokenSource.GetTokenAsync(cancellationToken).ConfigureAwait(false);
        await token.ApplyAsync(request, _tokenSource.TimeProvider, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Unauthorized || !token.CanBeManaged)
        {
            return response;
        }

        response.Dispose();
        var refreshed = await _tokenSource.RefreshAsync(token, cancellationToken).ConfigureAwait(false);
        using var retry = Clone(request, content);
        await refreshed.ApplyAsync(retry, _tokenSource.TimeProvider, cancellationToken).ConfigureAwait(false);
        return await base.SendAsync(retry, cancellationToken).ConfigureAwait(false);
    }

    private static HttpRequestMessage Clone(HttpRequestMessage original, byte[]? content)
    {
        var clone = new HttpRequestMessage(original.Method, original.RequestUri)
        {
            Version = original.Version,
            VersionPolicy = original.VersionPolicy,
        };

        foreach (var header in original.Headers)
        {
            if (!IsProofHeader(header.Key))
            {
                clone.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        if (content is not null)
        {
            clone.Content = new ByteArrayContent(content);
            foreach (var header in original.Content!.Headers)
            {
                if (!IsProofHeader(header.Key) && !header.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                {
                    clone.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
            }
        }

        IDictionary<string, object?> options = clone.Options;
        foreach (var option in original.Options)
        {
            options[option.Key] = option.Value;
        }

        return clone;
    }

    private static bool IsProofHeader(string name) =>
        name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Signature", StringComparison.OrdinalIgnoreCase)
        || name.Equals("Signature-Input", StringComparison.OrdinalIgnoreCase);
}
