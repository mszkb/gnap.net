using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Content-Digest creation and validation per RFC 9530.</summary>
public class ContentDigestTests
{
    private static readonly byte[] HelloWorldJson = Encoding.UTF8.GetBytes("{\"hello\": \"world\"}");

    [Fact]
    public void Sha256HeaderValue_MatchesRfc9530Example()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha256);

        Assert.Equal("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:", value);
    }

    [Fact]
    public void Sha512HeaderValue_MatchesRfc9421TestRequest()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha512);

        Assert.Equal(Rfc9421TestVectors.RequestContentDigest.Replace(" ", ""), value.Replace(" ", ""));
        Assert.Equal(ContentDigestValidation.Valid, ContentDigest.Validate(value, HelloWorldJson));
    }

    [Fact]
    public void MultipleAlgorithms_AllMustMatch()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson, ContentDigestAlgorithm.Sha256, ContentDigestAlgorithm.Sha512);

        Assert.Equal(ContentDigestValidation.Valid, ContentDigest.Validate(value, HelloWorldJson));
        Assert.Equal(ContentDigestValidation.Mismatch, ContentDigest.Validate(value, Encoding.UTF8.GetBytes("{}")));
    }

    [Fact]
    public void TamperedContent_IsDetected()
    {
        var value = ContentDigest.CreateHeaderValue(HelloWorldJson);

        Assert.Equal(ContentDigestValidation.Mismatch, ContentDigest.Validate(value, Encoding.UTF8.GetBytes("{\"hello\": \"World\"}")));
    }

    [Fact]
    public void UnsupportedAlgorithmOnly_IsReported()
    {
        Assert.Equal(
            ContentDigestValidation.NoSupportedAlgorithm,
            ContentDigest.Validate("md5=:XrY7u+Ae7tCTyyK7j1rNww==:", HelloWorldJson));
    }

    [Fact]
    public void MalformedHeader_IsReported()
    {
        Assert.Equal(ContentDigestValidation.Malformed, ContentDigest.Validate("sha-256=notbase64", HelloWorldJson));
        Assert.Equal(ContentDigestValidation.Malformed, ContentDigest.Validate("sha-256=\"a string\"", HelloWorldJson));
    }

    [Fact]
    public void DefaultAlgorithm_IsSha256()
    {
        Assert.StartsWith("sha-256=:", ContentDigest.CreateHeaderValue(HelloWorldJson), StringComparison.Ordinal);
    }
}
