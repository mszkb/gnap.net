using System.Diagnostics.CodeAnalysis;
using System.Text;
using Gnap.Core;

namespace Gnap.Client.Discovery;

/// <summary>
/// The <c>WWW-Authenticate: GNAP</c> challenge of an RS (RS-first AS discovery,
/// RFC 9635 Section 9.1): it names the AS grant endpoint (<c>as_uri</c>) and
/// optionally an access reference (<c>access</c>) the client can request
/// verbatim, plus a <c>referrer</c>.
/// </summary>
public sealed class GnapResourceChallenge
{
    private GnapResourceChallenge(Uri asUri, IReadOnlyDictionary<string, string> parameters)
    {
        AsUri = asUri;
        Parameters = parameters;
    }

    /// <summary>The grant endpoint of the AS protecting the resource.</summary>
    public Uri AsUri { get; }

    /// <summary>The access reference to request, when the RS supplied one.</summary>
    public string? Access => Parameters.GetValueOrDefault("access");

    /// <summary>The referrer the RS supplied, when present.</summary>
    public string? Referrer => Parameters.GetValueOrDefault("referrer");

    /// <summary>All challenge parameters (lowercase names).</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; }

    /// <summary>Reads the GNAP challenge of a (typically 401) RS response.</summary>
    public static bool TryParse(HttpResponseMessage response, [NotNullWhen(true)] out GnapResourceChallenge? challenge)
    {
        ArgumentNullException.ThrowIfNull(response);
        challenge = null;
        if (!response.Headers.TryGetValues("WWW-Authenticate", out var values))
        {
            return false;
        }

        foreach (var value in values)
        {
            if (TryParse(value, out challenge))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Parses a <c>WWW-Authenticate</c> field value carrying a GNAP challenge.</summary>
    public static bool TryParse(string? headerValue, [NotNullWhen(true)] out GnapResourceChallenge? challenge)
    {
        challenge = null;
        if (string.IsNullOrWhiteSpace(headerValue))
        {
            return false;
        }

        var text = headerValue.Trim();
        var scheme = GnapConstants.AuthorizationScheme;
        var start = FindScheme(text, scheme);
        if (start < 0)
        {
            return false;
        }

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
        var position = start + scheme.Length;
        while (position < text.Length)
        {
            SkipSeparators(text, ref position);
            var nameStart = position;
            while (position < text.Length && text[position] is not ('=' or ',' or ' '))
            {
                position++;
            }

            var name = text[nameStart..position].ToLowerInvariant();
            SkipWhitespace(text, ref position);
            if (name.Length == 0 || position >= text.Length || text[position] != '=')
            {
                // A token without '=' starts the next challenge (another scheme).
                break;
            }

            position++;
            SkipWhitespace(text, ref position);
            var value = ReadValue(text, ref position);
            parameters.TryAdd(name, value);
        }

        if (!parameters.TryGetValue("as_uri", out var asUri)
            || !Uri.TryCreate(asUri, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("https" or "http"))
        {
            return false;
        }

        challenge = new GnapResourceChallenge(uri, parameters);
        return true;
    }

    private static int FindScheme(string text, string scheme)
    {
        var index = 0;
        while ((index = text.IndexOf(scheme, index, StringComparison.OrdinalIgnoreCase)) >= 0)
        {
            var boundaryBefore = index == 0 || text[index - 1] is ' ' or ',';
            var after = index + scheme.Length;
            var boundaryAfter = after == text.Length || text[after] == ' ';
            if (boundaryBefore && boundaryAfter)
            {
                return index;
            }

            index = after;
        }

        return -1;
    }

    private static string ReadValue(string text, ref int position)
    {
        if (position < text.Length && text[position] == '"')
        {
            position++;
            var builder = new StringBuilder();
            while (position < text.Length && text[position] != '"')
            {
                if (text[position] == '\\' && position + 1 < text.Length)
                {
                    position++;
                }

                builder.Append(text[position]);
                position++;
            }

            position++; // closing quote
            return builder.ToString();
        }

        var start = position;
        while (position < text.Length && text[position] is not (',' or ' '))
        {
            position++;
        }

        return text[start..position];
    }

    private static void SkipSeparators(string text, ref int position)
    {
        while (position < text.Length && text[position] is ' ' or ',')
        {
            position++;
        }
    }

    private static void SkipWhitespace(string text, ref int position)
    {
        while (position < text.Length && text[position] == ' ')
        {
            position++;
        }
    }
}
