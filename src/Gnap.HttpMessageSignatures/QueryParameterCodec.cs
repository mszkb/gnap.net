using System.Text;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// Decoding and strict re-encoding of query parameter names and values for the
/// <c>@query-param</c> derived component (RFC 9421 Section 2.2.8).
/// </summary>
internal static class QueryParameterCodec
{
    /// <summary>
    /// Splits a raw query string (without the leading <c>?</c>) into decoded
    /// name/value pairs following application/x-www-form-urlencoded parsing:
    /// split on <c>&amp;</c>, split each part on the first <c>=</c>, replace
    /// <c>+</c> with space, then percent-decode as UTF-8.
    /// </summary>
    public static IEnumerable<(string Name, string Value)> Parse(string rawQuery)
    {
        if (rawQuery.Length == 0)
        {
            yield break;
        }

        foreach (var part in rawQuery.Split('&'))
        {
            if (part.Length == 0)
            {
                continue;
            }

            var eq = part.IndexOf('=');
            var rawName = eq < 0 ? part : part[..eq];
            var rawValue = eq < 0 ? string.Empty : part[(eq + 1)..];
            yield return (Decode(rawName), Decode(rawValue));
        }
    }

    /// <summary>Percent-decodes a form-encoded string (<c>+</c> means space).</summary>
    public static string Decode(string encoded)
    {
        var bytes = new List<byte>(encoded.Length);
        for (var i = 0; i < encoded.Length; i++)
        {
            var c = encoded[i];
            if (c == '+')
            {
                bytes.Add((byte)' ');
            }
            else if (c == '%' && i + 2 < encoded.Length
                && Uri.IsHexDigit(encoded[i + 1]) && Uri.IsHexDigit(encoded[i + 2]))
            {
                bytes.Add((byte)((Convert.ToInt32(encoded[i + 1].ToString(), 16) << 4)
                    | Convert.ToInt32(encoded[i + 2].ToString(), 16)));
                i += 2;
            }
            else
            {
                bytes.AddRange(Encoding.UTF8.GetBytes(new[] { c }));
            }
        }

        return Encoding.UTF8.GetString(bytes.ToArray());
    }

    /// <summary>
    /// Strictly re-encodes a decoded name or value: every byte outside the RFC 3986
    /// unreserved set is percent-encoded with uppercase hex digits.
    /// </summary>
    public static string Encode(string decoded)
    {
        var sb = new StringBuilder(decoded.Length);
        foreach (var b in Encoding.UTF8.GetBytes(decoded))
        {
            var c = (char)b;
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~')
            {
                sb.Append(c);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2"));
            }
        }

        return sb.ToString();
    }
}
