using System.Globalization;
using System.Text;

namespace Gnap.HttpMessageSignatures.StructuredFields;

/// <summary>
/// A bare item value of an RFC 8941 structured field: string, token, integer,
/// decimal, boolean or byte sequence.
/// </summary>
public abstract class SfValue
{
    private protected SfValue()
    {
    }

    /// <summary>Serializes this bare item into <paramref name="output"/> per RFC 8941 Section 4.1.3.1.</summary>
    internal abstract void SerializeTo(StringBuilder output);

    /// <summary>Returns the canonical RFC 8941 serialization of this bare item.</summary>
    public sealed override string ToString()
    {
        var sb = new StringBuilder();
        SerializeTo(sb);
        return sb.ToString();
    }
}

/// <summary>An RFC 8941 string: printable ASCII enclosed in double quotes.</summary>
public sealed class SfString : SfValue
{
    /// <summary>Creates a structured field string.</summary>
    /// <exception cref="ArgumentException">The value contains characters outside printable ASCII.</exception>
    public SfString(string value)
    {
        foreach (var c in value)
        {
            if (c < 0x20 || c > 0x7e)
            {
                throw new ArgumentException($"Structured field strings only allow printable ASCII; found U+{(int)c:X4}.", nameof(value));
            }
        }

        Value = value;
    }

    /// <summary>The string content without quotes or escaping.</summary>
    public string Value { get; }

    internal override void SerializeTo(StringBuilder output)
    {
        output.Append('"');
        foreach (var c in Value)
        {
            if (c is '"' or '\\')
            {
                output.Append('\\');
            }

            output.Append(c);
        }

        output.Append('"');
    }
}

/// <summary>An RFC 8941 token.</summary>
public sealed class SfToken : SfValue
{
    /// <summary>Creates a structured field token.</summary>
    /// <exception cref="ArgumentException">The value is not a valid token.</exception>
    public SfToken(string value)
    {
        if (value.Length == 0 || !(char.IsAsciiLetter(value[0]) || value[0] == '*'))
        {
            throw new ArgumentException("A token must start with an ASCII letter or '*'.", nameof(value));
        }

        for (var i = 1; i < value.Length; i++)
        {
            if (!IsTokenChar(value[i]))
            {
                throw new ArgumentException($"Invalid token character '{value[i]}'.", nameof(value));
            }
        }

        Value = value;
    }

    internal static bool IsTokenChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is ':' or '/' or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';

    /// <summary>The token text.</summary>
    public string Value { get; }

    internal override void SerializeTo(StringBuilder output) => output.Append(Value);
}

/// <summary>An RFC 8941 integer (at most 15 digits).</summary>
public sealed class SfInteger : SfValue
{
    internal const long Max = 999_999_999_999_999;

    /// <summary>Creates a structured field integer.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value has more than 15 digits.</exception>
    public SfInteger(long value)
    {
        if (value is > Max or < -Max)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Structured field integers are limited to 15 digits.");
        }

        Value = value;
    }

    /// <summary>The integer value.</summary>
    public long Value { get; }

    internal override void SerializeTo(StringBuilder output) => output.Append(Value.ToString(CultureInfo.InvariantCulture));
}

/// <summary>An RFC 8941 decimal (at most 12 integer digits and 3 fractional digits).</summary>
public sealed class SfDecimal : SfValue
{
    /// <summary>Creates a structured field decimal. The value is rounded to three fractional digits.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The integer part exceeds 12 digits.</exception>
    public SfDecimal(decimal value)
    {
        var rounded = Math.Round(value, 3, MidpointRounding.ToEven);
        if (Math.Abs(decimal.Truncate(rounded)) > 999_999_999_999m)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "Structured field decimals are limited to 12 integer digits.");
        }

        Value = rounded;
    }

    /// <summary>The decimal value, rounded to three fractional digits.</summary>
    public decimal Value { get; }

    internal override void SerializeTo(StringBuilder output)
    {
        var text = Value.ToString(CultureInfo.InvariantCulture);
        if (!text.Contains('.'))
        {
            output.Append(text).Append(".0");
            return;
        }

        text = text.TrimEnd('0');
        output.Append(text.EndsWith('.') ? text + "0" : text);
    }
}

/// <summary>An RFC 8941 boolean, serialized as <c>?1</c> or <c>?0</c>.</summary>
public sealed class SfBoolean : SfValue
{
    /// <summary>The boolean true value.</summary>
    public static readonly SfBoolean True = new(true);

    /// <summary>The boolean false value.</summary>
    public static readonly SfBoolean False = new(false);

    private SfBoolean(bool value) => Value = value;

    /// <summary>The boolean value.</summary>
    public bool Value { get; }

    internal override void SerializeTo(StringBuilder output) => output.Append(Value ? "?1" : "?0");
}

/// <summary>An RFC 8941 byte sequence, serialized as base64 between colons.</summary>
public sealed class SfBytes : SfValue
{
    private readonly byte[] _value;

    /// <summary>Creates a structured field byte sequence.</summary>
    public SfBytes(byte[] value) => _value = (byte[])value.Clone();

    /// <summary>The decoded bytes.</summary>
    public ReadOnlyMemory<byte> Value => _value;

    internal override void SerializeTo(StringBuilder output) =>
        output.Append(':').Append(Convert.ToBase64String(_value)).Append(':');
}
