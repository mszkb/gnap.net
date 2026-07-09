using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;

namespace Gnap.HttpMessageSignatures.AspNetCore;

/// <summary>An <see cref="IHttpMessageContext"/> over an incoming ASP.NET Core request.</summary>
public sealed class AspNetCoreRequestContext : IHttpMessageContext
{
    private readonly HttpRequest _request;

    /// <summary>Wraps the incoming request.</summary>
    public AspNetCoreRequestContext(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        _request = request;
    }

    /// <inheritdoc />
    public bool IsRequest => true;

    /// <inheritdoc />
    public string? Method => _request.Method;

    /// <inheritdoc />
    public Uri? TargetUri => new(_request.GetEncodedUrl(), UriKind.Absolute);

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

        return _request.Headers.TryGetValue(fieldName, out var values)
            ? values.Where(v => v is not null).Select(v => v!).ToArray()
            : [];
    }
}
