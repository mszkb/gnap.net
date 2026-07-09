using Gnap.HttpMessageSignatures.StructuredFields;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Parsing and canonical serialization of RFC 8941 structured fields.</summary>
public class StructuredFieldTests
{
    [Theory]
    [InlineData("a=1, b=2;x=1;y=2, c=(a b c)", "a=1, b=2;x=1;y=2, c=(a b c)")]
    [InlineData("  a=1 ,  b=2  ", "a=1, b=2")]
    [InlineData("flag, other=?0", "flag, other=?0")]
    [InlineData("bytes=:aGVsbG8=:", "bytes=:aGVsbG8=:")]
    [InlineData("nested=(\"x\";p=1 \"y\");q=\"z\"", "nested=(\"x\";p=1 \"y\");q=\"z\"")]
    public void Dictionary_RoundtripsCanonically(string input, string expected)
    {
        Assert.Equal(expected, SfParser.ParseDictionary(input).ToString());
    }

    [Theory]
    [InlineData("\"hello\"", typeof(SfString))]
    [InlineData("token", typeof(SfToken))]
    [InlineData("*special/token:x", typeof(SfToken))]
    [InlineData("42", typeof(SfInteger))]
    [InlineData("-13.37", typeof(SfDecimal))]
    [InlineData("?1", typeof(SfBoolean))]
    [InlineData(":aGVsbG8=:", typeof(SfBytes))]
    public void BareItems_ParseToExpectedTypes(string input, Type expectedType)
    {
        Assert.IsType(expectedType, SfParser.ParseItem(input).Value);
    }

    [Fact]
    public void String_EscapesQuotesAndBackslashes()
    {
        var item = SfParser.ParseItem("\"say \\\"hi\\\" \\\\ done\"");

        Assert.Equal("say \"hi\" \\ done", Assert.IsType<SfString>(item.Value).Value);
        Assert.Equal("\"say \\\"hi\\\" \\\\ done\"", item.ToString());
    }

    [Fact]
    public void InnerList_PreservesItemAndListParameters()
    {
        var list = SfParser.ParseList("(\"a\" \"b\";x=1);y=2, single");

        Assert.Equal(2, list.Count);
        var inner = Assert.IsType<SfInnerList>(list[0]);
        Assert.Equal(2, inner.Items.Count);
        Assert.Equal("(\"a\" \"b\";x=1);y=2", inner.ToString());
    }

    [Fact]
    public void DuplicateDictionaryKey_LastValueWins()
    {
        var dict = SfParser.ParseDictionary("a=1, a=2");

        Assert.Equal("a=2", dict.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("a=1,")]
    [InlineData("=1")]
    [InlineData("A=1")]
    [InlineData("a=\"unterminated")]
    [InlineData("a=?2")]
    [InlineData("a=1234567890123456")]
    [InlineData("a=:not base64!:")]
    [InlineData("a=(1 2")]
    public void MalformedDictionaries_Throw(string input)
    {
        if (input.Length == 0)
        {
            // An empty dictionary is valid; nothing to assert beyond parsing.
            Assert.Empty(SfParser.ParseDictionary(input));
            return;
        }

        Assert.Throws<SfParseException>(() => SfParser.ParseDictionary(input));
    }

    [Theory]
    [InlineData(999_999_999_999_999L, "999999999999999")]
    [InlineData(-999_999_999_999_999L, "-999999999999999")]
    public void IntegerLimits_Serialize(long value, string expected)
    {
        Assert.Equal(expected, new SfInteger(value).ToString());
    }

    [Fact]
    public void IntegerBeyondLimit_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new SfInteger(1_000_000_000_000_000));
    }

    [Theory]
    [InlineData("1.5", "1.5")]
    [InlineData("1.0", "1.0")]
    [InlineData("-7.250", "-7.25")]
    public void Decimals_SerializeCanonically(string input, string expected)
    {
        Assert.Equal(expected, SfParser.ParseItem(input).ToString());
    }

    [Fact]
    public void NonAsciiString_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => new SfString("schöne Grüße"));
    }
}
