using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;

namespace Gnap.Core;

/// <summary>
/// Presents and reads GNAP access tokens in the HTTP <c>Authorization</c> field
/// (RFC 9635 Section 7.2): <c>Authorization: GNAP &lt;token value&gt;</c>, where the
/// token value uses the <c>token68</c> character set of RFC 9110. For key-bound
/// tokens the request must additionally carry a key proof that covers the
/// <c>Authorization</c> field (see <see cref="Proofing.HttpSigKeyProofer"/>).
/// </summary>
public static class GnapAuthorization
{
    /// <summary>Formats the <c>Authorization</c> field value for an access token.</summary>
    /// <exception cref="GnapException">The token value is not a valid <c>token68</c>.</exception>
    public static string CreateHeaderValue(string accessTokenValue)
    {
        RequireToken68(accessTokenValue);
        return $"{GnapConstants.AuthorizationScheme} {accessTokenValue}";
    }

    /// <summary>Sets the <c>Authorization</c> header of an outgoing request to the access token.</summary>
    /// <exception cref="GnapException">The token value is not a valid <c>token68</c>.</exception>
    public static void Apply(HttpRequestMessage request, string accessTokenValue)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireToken68(accessTokenValue);
        request.Headers.Authorization = new AuthenticationHeaderValue(GnapConstants.AuthorizationScheme, accessTokenValue);
    }

    /// <summary>
    /// Extracts the access token value from an <c>Authorization</c> field value.
    /// The scheme is matched case-insensitively (RFC 9110 Section 11.1); returns
    /// <see langword="false"/> for other schemes or a malformed token.
    /// </summary>
    public static bool TryParse(string? headerValue, [NotNullWhen(true)] out string? accessTokenValue)
    {
        accessTokenValue = null;
        if (string.IsNullOrEmpty(headerValue))
        {
            return false;
        }

        var span = headerValue.AsSpan().Trim();
        var scheme = GnapConstants.AuthorizationScheme;
        if (span.Length <= scheme.Length
            || !span[..scheme.Length].Equals(scheme, StringComparison.OrdinalIgnoreCase)
            || span[scheme.Length] != ' ')
        {
            return false;
        }

        var token = span[(scheme.Length + 1)..].TrimStart(' ');
        if (!IsToken68(token))
        {
            return false;
        }

        accessTokenValue = token.ToString();
        return true;
    }

    /// <summary>Whether the value matches the RFC 9110 <c>token68</c> syntax.</summary>
    public static bool IsToken68(ReadOnlySpan<char> value)
    {
        var end = value.Length;
        while (end > 0 && value[end - 1] == '=')
        {
            end--;
        }

        if (end == 0)
        {
            return false;
        }

        foreach (var c in value[..end])
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~' or '+' or '/'))
            {
                return false;
            }
        }

        return true;
    }

    private static void RequireToken68(string accessTokenValue)
    {
        ArgumentNullException.ThrowIfNull(accessTokenValue);
        if (!IsToken68(accessTokenValue))
        {
            throw new GnapException("A GNAP access token value must use the token68 character set.");
        }
    }
}
