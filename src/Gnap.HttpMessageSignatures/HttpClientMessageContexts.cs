namespace Gnap.HttpMessageSignatures;

/// <summary>An <see cref="IHttpMessageContext"/> over <see cref="HttpRequestMessage"/>.</summary>
public sealed class HttpRequestMessageContext : IHttpMessageContext
{
    private readonly HttpRequestMessage _request;

    /// <summary>Wraps the request. The request URI must be absolute.</summary>
    public HttpRequestMessageContext(HttpRequestMessage request)
    {
        ArgumentNullException.ThrowIfNull(request);
        _request = request;
    }

    /// <inheritdoc />
    public bool IsRequest => true;

    /// <inheritdoc />
    public string? Method => _request.Method.Method;

    /// <inheritdoc />
    public Uri? TargetUri => _request.RequestUri;

    /// <inheritdoc />
    public int? StatusCode => null;

    /// <inheritdoc />
    public IHttpMessageContext? AssociatedRequest => null;

    /// <inheritdoc />
    public IReadOnlyList<string> GetFieldValues(string fieldName, bool fromTrailers = false)
    {
        if (fromTrailers)
        {
            return [];
        }

        if (_request.Headers.TryGetValues(fieldName, out var values))
        {
            return values.ToArray();
        }

        if (_request.Content is not null && _request.Content.Headers.TryGetValues(fieldName, out var contentValues))
        {
            return contentValues.ToArray();
        }

        // The Host header is filled in by HttpClient at send time; synthesize it
        // from the target URI so it can be covered before sending.
        if (string.Equals(fieldName, "host", StringComparison.OrdinalIgnoreCase) && _request.RequestUri is { } uri)
        {
            return [uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}"];
        }

        return [];
    }
}

/// <summary>An <see cref="IHttpMessageContext"/> over <see cref="HttpResponseMessage"/>.</summary>
public sealed class HttpResponseMessageContext : IHttpMessageContext
{
    private readonly HttpResponseMessage _response;

    /// <summary>Wraps the response; the associated request is taken from <see cref="HttpResponseMessage.RequestMessage"/>.</summary>
    public HttpResponseMessageContext(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        _response = response;
    }

    /// <inheritdoc />
    public bool IsRequest => false;

    /// <inheritdoc />
    public string? Method => null;

    /// <inheritdoc />
    public Uri? TargetUri => null;

    /// <inheritdoc />
    public int? StatusCode => (int)_response.StatusCode;

    /// <inheritdoc />
    public IHttpMessageContext? AssociatedRequest =>
        _response.RequestMessage is { } request ? new HttpRequestMessageContext(request) : null;

    /// <inheritdoc />
    public IReadOnlyList<string> GetFieldValues(string fieldName, bool fromTrailers = false)
    {
        if (fromTrailers)
        {
            return _response.TrailingHeaders.TryGetValues(fieldName, out var trailerValues)
                ? trailerValues.ToArray()
                : [];
        }

        if (_response.Headers.TryGetValues(fieldName, out var values))
        {
            return values.ToArray();
        }

        if (_response.Content.Headers.TryGetValues(fieldName, out var contentValues))
        {
            return contentValues.ToArray();
        }

        return [];
    }
}
