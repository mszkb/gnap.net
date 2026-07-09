namespace Gnap.Core;

/// <summary>
/// The exception thrown when GNAP protocol data cannot be processed, for example
/// because a JSON Web Key is incomplete or a key format is not supported.
/// </summary>
public sealed class GnapException : Exception
{
    /// <summary>Creates the exception with a description of the failure.</summary>
    public GnapException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with a description and an inner cause.</summary>
    public GnapException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
