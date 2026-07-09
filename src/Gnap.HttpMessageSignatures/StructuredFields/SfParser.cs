using System.Globalization;
using System.Text;

namespace Gnap.HttpMessageSignatures.StructuredFields;

/// <summary>The exception thrown when a structured field value cannot be parsed.</summary>
public sealed class SfParseException : FormatException
{
    /// <summary>Creates the exception with a description of the syntax error.</summary>
    public SfParseException(string message)
        : base(message)
    {
    }
}

/// <summary>Parser for RFC 8941 structured field values.</summary>
public static class SfParser
{
    /// <summary>Parses a structured field value as a dictionary.</summary>
    /// <exception cref="SfParseException">The input is not a valid dictionary.</exception>
    public static SfDictionary ParseDictionary(string input)
    {
        var p = new Cursor(input);
        var dict = new SfDictionary();
        p.SkipSpaces();
        while (!p.AtEnd)
        {
            var key = p.ParseKey();
            SfMember member;
            if (p.TryConsume('='))
            {
                member = p.ParseItemOrInnerList();
            }
            else
            {
                member = new SfItem(SfBoolean.True, p.ParseParameters());
            }

            dict.Add(key, member);
            p.SkipOws();
            if (p.AtEnd)
            {
                return Finish(p, dict);
            }

            p.Expect(',');
            p.SkipOws();
            if (p.AtEnd)
            {
                throw new SfParseException("Dictionary has a trailing comma.");
            }
        }

        return Finish(p, dict);
    }

    /// <summary>Parses a structured field value as a list.</summary>
    /// <exception cref="SfParseException">The input is not a valid list.</exception>
    public static SfList ParseList(string input)
    {
        var p = new Cursor(input);
        var list = new SfList();
        p.SkipSpaces();
        while (!p.AtEnd)
        {
            list.Add(p.ParseItemOrInnerList());
            p.SkipOws();
            if (p.AtEnd)
            {
                return Finish(p, list);
            }

            p.Expect(',');
            p.SkipOws();
            if (p.AtEnd)
            {
                throw new SfParseException("List has a trailing comma.");
            }
        }

        return Finish(p, list);
    }

    /// <summary>Parses a structured field value as a single item.</summary>
    /// <exception cref="SfParseException">The input is not a valid item.</exception>
    public static SfItem ParseItem(string input)
    {
        var p = new Cursor(input);
        p.SkipSpaces();
        var item = p.ParseItem();
        p.SkipSpaces();
        if (!p.AtEnd)
        {
            throw new SfParseException("Unexpected trailing characters after item.");
        }

        return item;
    }

    private static T Finish<T>(Cursor p, T value)
    {
        p.SkipSpaces();
        if (!p.AtEnd)
        {
            throw new SfParseException("Unexpected trailing characters.");
        }

        return value;
    }

    private sealed class Cursor(string input)
    {
        private readonly string _input = input;
        private int _pos;

        public bool AtEnd => _pos >= _input.Length;

        private char Peek => _input[_pos];

        public void SkipSpaces()
        {
            while (!AtEnd && Peek == ' ')
            {
                _pos++;
            }
        }

        public void SkipOws()
        {
            while (!AtEnd && Peek is ' ' or '\t')
            {
                _pos++;
            }
        }

        public bool TryConsume(char c)
        {
            if (!AtEnd && Peek == c)
            {
                _pos++;
                return true;
            }

            return false;
        }

        public void Expect(char c)
        {
            if (!TryConsume(c))
            {
                throw new SfParseException($"Expected '{c}' at position {_pos}.");
            }
        }

        public SfMember ParseItemOrInnerList() => !AtEnd && Peek == '(' ? ParseInnerList() : ParseItem();

        public SfInnerList ParseInnerList()
        {
            Expect('(');
            var items = new List<SfItem>();
            while (true)
            {
                SkipSpaces();
                if (AtEnd)
                {
                    throw new SfParseException("Unterminated inner list.");
                }

                if (TryConsume(')'))
                {
                    return new SfInnerList(items, ParseParameters());
                }

                items.Add(ParseItem());
                if (AtEnd || (Peek != ' ' && Peek != ')'))
                {
                    throw new SfParseException("Inner list items must be separated by spaces.");
                }
            }
        }

        public SfItem ParseItem()
        {
            var value = ParseBareItem();
            return new SfItem(value, ParseParameters());
        }

        public SfParameters ParseParameters()
        {
            var parameters = new SfParameters();
            while (TryConsume(';'))
            {
                SkipSpaces();
                var key = ParseKey();
                var value = TryConsume('=') ? ParseBareItem() : SfBoolean.True;
                parameters.Add(key, value);
            }

            return parameters;
        }

        public string ParseKey()
        {
            if (AtEnd || !(char.IsAsciiLetterLower(Peek) || Peek == '*'))
            {
                throw new SfParseException($"Expected a key at position {_pos}.");
            }

            var start = _pos;
            while (!AtEnd && SfParameters.IsKeyChar(Peek))
            {
                _pos++;
            }

            return _input[start.._pos];
        }

        private SfValue ParseBareItem()
        {
            if (AtEnd)
            {
                throw new SfParseException("Expected a bare item but reached the end of input.");
            }

            var c = Peek;
            if (c == '-' || char.IsAsciiDigit(c))
            {
                return ParseNumber();
            }

            return c switch
            {
                '"' => ParseString(),
                ':' => ParseByteSequence(),
                '?' => ParseBoolean(),
                _ when char.IsAsciiLetter(c) || c == '*' => ParseToken(),
                _ => throw new SfParseException($"Unexpected character '{c}' at position {_pos}."),
            };
        }

        private SfValue ParseNumber()
        {
            var start = _pos;
            TryConsume('-');
            var intDigits = 0;
            while (!AtEnd && char.IsAsciiDigit(Peek))
            {
                _pos++;
                intDigits++;
            }

            if (intDigits == 0)
            {
                throw new SfParseException("A number requires at least one digit.");
            }

            if (!AtEnd && Peek == '.')
            {
                if (intDigits > 12)
                {
                    throw new SfParseException("Decimal integer part is limited to 12 digits.");
                }

                _pos++;
                var fracDigits = 0;
                while (!AtEnd && char.IsAsciiDigit(Peek))
                {
                    _pos++;
                    fracDigits++;
                }

                if (fracDigits is 0 or > 3)
                {
                    throw new SfParseException("Decimal fraction must have one to three digits.");
                }

                return new SfDecimal(decimal.Parse(_input[start.._pos], CultureInfo.InvariantCulture));
            }

            if (intDigits > 15)
            {
                throw new SfParseException("Integers are limited to 15 digits.");
            }

            return new SfInteger(long.Parse(_input[start.._pos], CultureInfo.InvariantCulture));
        }

        private SfString ParseString()
        {
            Expect('"');
            var sb = new StringBuilder();
            while (true)
            {
                if (AtEnd)
                {
                    throw new SfParseException("Unterminated string.");
                }

                var c = _input[_pos++];
                if (c == '"')
                {
                    return new SfString(sb.ToString());
                }

                if (c == '\\')
                {
                    if (AtEnd)
                    {
                        throw new SfParseException("Unterminated escape sequence in string.");
                    }

                    var escaped = _input[_pos++];
                    if (escaped is not ('"' or '\\'))
                    {
                        throw new SfParseException($"Invalid escape sequence '\\{escaped}' in string.");
                    }

                    sb.Append(escaped);
                    continue;
                }

                if (c < 0x20 || c > 0x7e)
                {
                    throw new SfParseException("Strings only allow printable ASCII characters.");
                }

                sb.Append(c);
            }
        }

        private SfToken ParseToken()
        {
            var start = _pos;
            _pos++;
            while (!AtEnd && SfToken.IsTokenChar(Peek))
            {
                _pos++;
            }

            return new SfToken(_input[start.._pos]);
        }

        private SfBytes ParseByteSequence()
        {
            Expect(':');
            var start = _pos;
            while (!AtEnd && Peek != ':')
            {
                _pos++;
            }

            Expect(':');
            var b64 = _input[start..(_pos - 1)];
            try
            {
                return new SfBytes(Convert.FromBase64String(b64));
            }
            catch (FormatException)
            {
                throw new SfParseException("Invalid base64 in byte sequence.");
            }
        }

        private SfBoolean ParseBoolean()
        {
            Expect('?');
            if (TryConsume('1'))
            {
                return SfBoolean.True;
            }

            if (TryConsume('0'))
            {
                return SfBoolean.False;
            }

            throw new SfParseException("A boolean must be '?0' or '?1'.");
        }
    }
}
