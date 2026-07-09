namespace Gnap.Core;

/// <summary>Protocol constants of RFC 9635.</summary>
public static class GnapConstants
{
    /// <summary>The HTTP authentication scheme for presenting GNAP access tokens.</summary>
    public const string AuthorizationScheme = "GNAP";

    /// <summary>The required <c>tag</c> signature parameter value for GNAP HTTP message signatures.</summary>
    public const string HttpSignatureTag = "gnap";

    /// <summary>The media type of grant requests and responses.</summary>
    public const string MediaType = "application/json";
}
