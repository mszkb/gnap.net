namespace Gnap.HttpMessageSignatures;

/// <summary>
/// The exception thrown when an HTTP message signature cannot be created or a
/// signature base cannot be assembled, for example because a covered component
/// is missing from the message.
/// </summary>
public sealed class HttpMessageSignatureException : Exception
{
    /// <summary>Creates the exception with a description of the failure.</summary>
    public HttpMessageSignatureException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a description and an inner cause.</summary>
    public HttpMessageSignatureException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
