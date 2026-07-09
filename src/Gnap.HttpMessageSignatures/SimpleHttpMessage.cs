namespace Gnap.HttpMessageSignatures;

/// <summary>
/// A minimal in-memory <see cref="IHttpMessageContext"/> for tests, tooling and
/// scenarios outside <c>HttpClient</c> / ASP.NET Core.
/// </summary>
public sealed class SimpleHttpMessage : IHttpMessageContext
{
    private readonly List<(string Name, string Value)> _headers = [];
    private readonly List<(string Name, string Value)> _trailers = [];

    private SimpleHttpMessage()
    {
    }

    /// <summary>Creates a request message context.</summary>
    public static SimpleHttpMessage Request(string method, string targetUri) => new()
    {
        IsRequest = true,
        Method = method.ToUpperInvariant(),
        TargetUri = new Uri(targetUri, UriKind.Absolute),
    };

    /// <summary>Creates a response message context, optionally linked to its request.</summary>
    public static SimpleHttpMessage Response(int statusCode, IHttpMessageContext? request = null) => new()
    {
        IsRequest = false,
        StatusCode = statusCode,
        AssociatedRequest = request,
    };

    /// <inheritdoc />
    public bool IsRequest { get; private init; }

    /// <inheritdoc />
    public string? Method { get; private init; }

    /// <inheritdoc />
    public Uri? TargetUri { get; private init; }

    /// <inheritdoc />
    public int? StatusCode { get; private init; }

    /// <inheritdoc />
    public IHttpMessageContext? AssociatedRequest { get; private init; }

    /// <summary>Appends a header field instance (repeatable for multi-value fields).</summary>
    public SimpleHttpMessage WithHeader(string name, string value)
    {
        _headers.Add((name, value));
        return this;
    }

    /// <summary>Appends a trailer field instance.</summary>
    public SimpleHttpMessage WithTrailer(string name, string value)
    {
        _trailers.Add((name, value));
        return this;
    }

    /// <inheritdoc />
    public IReadOnlyList<string> GetFieldValues(string fieldName, bool fromTrailers = false)
    {
        var source = fromTrailers ? _trailers : _headers;
        return source
            .Where(h => string.Equals(h.Name, fieldName, StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToArray();
    }
}
