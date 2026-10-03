using Xunit;

namespace Gnap.Core.Tests;

public class GnapAuthorizationTests
{
    [Fact]
    public void CreateHeaderValue_UsesGnapScheme()
    {
        Assert.Equal("GNAP OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0", GnapAuthorization.CreateHeaderValue("OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0"));
    }

    [Fact]
    public void Apply_SetsAuthorizationHeader()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://rs.example.com/");
        GnapAuthorization.Apply(request, "abc.def~ghi==");
        Assert.Equal("GNAP abc.def~ghi==", request.Headers.Authorization!.ToString());
    }

    [Theory]
    [InlineData("GNAP abc", "abc")]
    [InlineData("gnap abc", "abc")]
    [InlineData("  GNAP   a+b/c==  ", "a+b/c==")]
    public void TryParse_AcceptsValidValues(string header, string expected)
    {
        Assert.True(GnapAuthorization.TryParse(header, out var token));
        Assert.Equal(expected, token);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer abc")]
    [InlineData("GNAPabc")]
    [InlineData("GNAP ")]
    [InlineData("GNAP a b")]
    [InlineData("GNAP ===")]
    [InlineData("GNAP a=b")]
    public void TryParse_RejectsInvalidValues(string? header)
    {
        Assert.False(GnapAuthorization.TryParse(header, out _));
    }

    [Theory]
    [InlineData("has space")]
    [InlineData("quote\"")]
    [InlineData("")]
    public void InvalidTokenValue_Throws(string value)
    {
        Assert.Throws<GnapException>(() => GnapAuthorization.CreateHeaderValue(value));
    }
}
