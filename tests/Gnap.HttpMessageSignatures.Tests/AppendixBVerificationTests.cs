using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// Verifies the actual signature values of RFC 9421 Appendix B against the
/// specification keys. RSA-PSS and ECDSA are randomized, so only verification is
/// checked for those; HMAC and Ed25519 are deterministic and additionally checked
/// by re-signing.
/// </summary>
public class AppendixBVerificationTests
{
    private static HttpMessageVerifier CreateVerifier() => new(new VerificationOptions
    {
        KeyResolver = Rfc9421TestVectors.AllKeys(),
    });

    private static async Task<VerificationResult> VerifyAsync(SimpleHttpMessage message, string signatureInput, string signature)
    {
        message.WithHeader("Signature-Input", signatureInput).WithHeader("Signature", signature);
        return await CreateVerifier().VerifyAsync(message);
    }

    [Theory]
    [InlineData(Rfc9421TestVectors.B21SignatureInput, Rfc9421TestVectors.B21Signature)]
    [InlineData(Rfc9421TestVectors.B22SignatureInput, Rfc9421TestVectors.B22Signature)]
    [InlineData(Rfc9421TestVectors.B23SignatureInput, Rfc9421TestVectors.B23Signature)]
    [InlineData(Rfc9421TestVectors.B25SignatureInput, Rfc9421TestVectors.B25Signature)]
    [InlineData(Rfc9421TestVectors.B26SignatureInput, Rfc9421TestVectors.B26Signature)]
    public async Task RequestSignatures_VerifyAgainstSpecKeys(string signatureInput, string signature)
    {
        var result = await VerifyAsync(Rfc9421TestVectors.TestRequest(), signatureInput, signature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task ResponseSignature_B24_VerifiesAgainstEccKey()
    {
        var result = await VerifyAsync(Rfc9421TestVectors.TestResponse(), Rfc9421TestVectors.B24SignatureInput, Rfc9421TestVectors.B24Signature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task ProxySignature_B3_VerifiesAgainstEccKey()
    {
        var result = await VerifyAsync(Rfc9421TestVectors.ProxyRequest(), Rfc9421TestVectors.TtrpSignatureInput, Rfc9421TestVectors.TtrpSignature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public void HmacSignature_B25_IsReproducedExactly()
    {
        var algorithm = SignatureAlgorithm.HmacSha256(Convert.FromBase64String(Rfc9421TestVectors.SharedSecretBase64));

        var signature = algorithm.Sign(Encoding.UTF8.GetBytes(Rfc9421TestVectors.B25ExpectedBase));

        Assert.Equal("pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=", Convert.ToBase64String(signature));
    }

    [Fact]
    public void Ed25519Signature_B26_IsReproducedExactly()
    {
        var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(Rfc9421TestVectors.Ed25519TestKeyPem);
        var algorithm = SignatureAlgorithm.Ed25519(publicKey, privateKey);

        var signature = algorithm.Sign(Encoding.UTF8.GetBytes(Rfc9421TestVectors.B26ExpectedBase));

        Assert.Equal(
            "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==",
            Convert.ToBase64String(signature));
    }

    [Fact]
    public async Task Transform_OriginalMessage_Verifies()
    {
        var result = await VerifyAsync(Rfc9421TestVectors.TransformRequest(), Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task Transform_AddingUncoveredHeaderAndQueryParam_StillVerifies()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.org/demo?name1=Value1&Name2=value2&param=added")
            .WithHeader("Host", "example.org")
            .WithHeader("Accept", "application/json")
            .WithHeader("Accept", "*/*")
            .WithHeader("Accept-Language", "en-US,en;q=0.5");

        var result = await VerifyAsync(message, Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task Transform_CollapsingAcceptIntoOneLine_StillVerifies()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.org/demo?name1=Value1&Name2=value2")
            .WithHeader("Host", "example.org")
            .WithHeader("Referer", "https://developer.example.org/demo")
            .WithHeader("Accept", "application/json, */*");

        var result = await VerifyAsync(message, Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task Transform_ChangedMethodAndAuthority_FailsVerification()
    {
        var message = Rfc9421TestVectors.TransformRequest(authority: "example.com", method: "POST");

        var result = await VerifyAsync(message, Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Transform_ReorderedAcceptValues_FailsVerification()
    {
        var message = SimpleHttpMessage.Request("GET", "https://example.org/demo?name1=Value1&Name2=value2")
            .WithHeader("Host", "example.org")
            .WithHeader("Accept", "*/*")
            .WithHeader("Accept", "application/json");

        var result = await VerifyAsync(message, Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature);

        Assert.False(result.Succeeded);
    }
}
