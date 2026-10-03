using System.Net;
using Gnap.Core.Models;

namespace Gnap.Client;

/// <summary>
/// The base exception of the GNAP client: the AS could not be reached, answered
/// with an unexpected status or malformed content, or a client-side protocol
/// check failed.
/// </summary>
public class GnapClientException : Exception
{
    /// <summary>Creates the exception with a description of the failure.</summary>
    public GnapClientException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a description and an inner cause.</summary>
    public GnapClientException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>Creates the exception for an HTTP response with an unexpected status.</summary>
    public GnapClientException(string message, HttpStatusCode? statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    /// <summary>The HTTP status of the response that caused the failure, when there was one.</summary>
    public HttpStatusCode? StatusCode { get; }
}

/// <summary>
/// The AS answered with a GNAP error (RFC 9635 Section 3.6). The typed
/// <see cref="Code"/> can be compared against the registered codes, e.g.
/// <c>ex.Code == GnapErrorCode.UserDenied</c>.
/// </summary>
public sealed class GnapProtocolException : GnapClientException
{
    /// <summary>Creates the exception from the AS's error response.</summary>
    public GnapProtocolException(GrantResponse response, HttpStatusCode statusCode)
        : base(Describe(response), statusCode)
    {
        ArgumentNullException.ThrowIfNull(response);
        Response = response;
        Error = response.Error!;
    }

    /// <summary>The error returned by the AS.</summary>
    public GnapError Error { get; }

    /// <summary>The machine-readable error code.</summary>
    public GnapErrorCode Code => Error.Code;

    /// <summary>
    /// The complete response; for some errors (e.g. <c>too_fast</c>) the AS includes a
    /// <c>continue</c> field the client can keep using.
    /// </summary>
    public GrantResponse Response { get; }

    private static string Describe(GrantResponse response)
    {
        var error = response?.Error ?? throw new ArgumentException("The response carries no error.", nameof(response));
        return error.Description is { Length: > 0 } description
            ? $"The authorization server returned '{error.Code}': {description}"
            : $"The authorization server returned '{error.Code}'.";
    }
}

/// <summary>
/// The interaction finish callback could not be trusted (RFC 9635 Section 4.2.3):
/// the <c>hash</c> or <c>interact_ref</c> is missing, or the hash does not match.
/// The grant must not be continued with this callback.
/// </summary>
public sealed class GnapInteractionException : GnapClientException
{
    /// <summary>Creates the exception with a description of the failure.</summary>
    public GnapInteractionException(string message)
        : base(message)
    {
    }
}
