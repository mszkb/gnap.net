namespace Gnap.HttpMessageSignatures;

/// <summary>
/// A read-only view of the HTTP message being signed or verified, independent of
/// the concrete HTTP stack (System.Net.Http, ASP.NET Core, tests).
/// </summary>
public interface IHttpMessageContext
{
    /// <summary>Whether this message is a request (otherwise it is a response).</summary>
    bool IsRequest { get; }

    /// <summary>The request method, for requests.</summary>
    string? Method { get; }

    /// <summary>The absolute target URI, for requests.</summary>
    Uri? TargetUri { get; }

    /// <summary>The status code, for responses.</summary>
    int? StatusCode { get; }

    /// <summary>For responses: the request this message answers, used by the <c>req</c> component flag.</summary>
    IHttpMessageContext? AssociatedRequest { get; }

    /// <summary>
    /// Returns all values of the named field in message order, or an empty list if
    /// the field is absent. Field names are matched case-insensitively.
    /// </summary>
    IReadOnlyList<string> GetFieldValues(string fieldName, bool fromTrailers = false);
}
