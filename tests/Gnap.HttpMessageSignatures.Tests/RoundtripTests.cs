using System.Security.Cryptography;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Sign→verify roundtrips with freshly generated keys for every algorithm.</summary>
public class RoundtripTests
{
    public static TheoryData<string> Algorithms => new()
    {
        "rsa-pss-sha512",
        "rsa-v1_5-sha256",
        "ecdsa-p256-sha256",
        "ecdsa-p384-sha384",
        "hmac-sha256",
        "ed25519",
    };

    internal static SignatureAlgorithm CreateFreshKey(string name) => name switch
    {
        "rsa-pss-sha512" => SignatureAlgorithm.RsaPssSha512(RSA.Create(2048)),
        "rsa-v1_5-sha256" => SignatureAlgorithm.RsaV15Sha256(RSA.Create(2048)),
        "ecdsa-p256-sha256" => SignatureAlgorithm.EcdsaP256Sha256(ECDsa.Create(ECCurve.NamedCurves.nistP256)),
        "ecdsa-p384-sha384" => SignatureAlgorithm.EcdsaP384Sha384(ECDsa.Create(ECCurve.NamedCurves.nistP384)),
        "hmac-sha256" => SignatureAlgorithm.HmacSha256(RandomNumberGenerator.GetBytes(64)),
        "ed25519" => CreateFreshEd25519(),
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };

    private static SignatureAlgorithm CreateFreshEd25519()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        return SignatureAlgorithm.Ed25519(publicKey: null, privateKey: seed);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task SignedRequest_VerifiesWithSameKey(string algorithmName)
    {
        var algorithm = CreateFreshKey(algorithmName);
        var signer = new HttpMessageSigner(algorithm)
        {
            KeyId = "roundtrip-key",
            CoveredComponents =
            [
                SignatureComponent.Method,
                SignatureComponent.TargetUri,
                SignatureComponent.Field("date"),
            ],
            Lifetime = TimeSpan.FromMinutes(5),
            NonceLength = 16,
            Tag = "roundtrip-test",
        };
        var message = SimpleHttpMessage.Request("POST", "https://example.com/api/items?filter=all")
            .WithHeader("Date", DateTimeOffset.UtcNow.ToString("r"));

        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("roundtrip-key", algorithm),
        });
        var result = await verifier.VerifyAsync(message);

        Assert.True(result.Succeeded, result.FailureReason);
        var verification = Assert.Single(result.Signatures);
        Assert.Equal("sig1", verification.Label);
        Assert.Equal("roundtrip-test", verification.Parameters!.Tag);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public async Task TamperedTarget_FailsVerificationWithSameKey(string algorithmName)
    {
        var algorithm = CreateFreshKey(algorithmName);
        var signer = new HttpMessageSigner(algorithm)
        {
            KeyId = "roundtrip-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        };
        var message = SimpleHttpMessage.Request("POST", "https://example.com/api/items");
        var signed = signer.Sign(message);

        var tampered = SimpleHttpMessage.Request("POST", "https://example.com/api/admin")
            .WithHeader("Signature-Input", signed.SignatureInput)
            .WithHeader("Signature", signed.Signature);

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("roundtrip-key", algorithm),
        });
        var result = await verifier.VerifyAsync(tampered);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ResponseSignature_RoundtripsIncludingRequestComponents()
    {
        var algorithm = CreateFreshKey("ed25519");
        var signer = new HttpMessageSigner(algorithm)
        {
            KeyId = "response-key",
            CoveredComponents =
            [
                SignatureComponent.Status,
                SignatureComponent.Method.WithRequest(),
                SignatureComponent.TargetUri.WithRequest(),
            ],
        };
        var request = SimpleHttpMessage.Request("GET", "https://example.com/resource/1");
        var response = SimpleHttpMessage.Response(200, request);

        var signed = signer.Sign(response);
        response.WithHeader("Signature-Input", signed.SignatureInput);
        response.WithHeader("Signature", signed.Signature);

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("response-key", algorithm),
        });
        var result = await verifier.VerifyAsync(response);

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task MultipleSignatures_AllVerify()
    {
        var first = CreateFreshKey("ed25519");
        var second = CreateFreshKey("ecdsa-p256-sha256");
        var message = SimpleHttpMessage.Request("GET", "https://example.com/multi");

        var firstResult = new HttpMessageSigner(first)
        {
            Label = "client",
            KeyId = "key-1",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        }.Sign(message);
        message.WithHeader("Signature-Input", firstResult.SignatureInput);
        message.WithHeader("Signature", firstResult.Signature);

        var secondResult = new HttpMessageSigner(second)
        {
            Label = "gateway",
            KeyId = "key-2",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        }.Sign(message);
        message.WithHeader("Signature-Input", secondResult.SignatureInput);
        message.WithHeader("Signature", secondResult.Signature);

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("key-1", first).Add("key-2", second),
        });

        var all = await verifier.VerifyAsync(message);
        Assert.True(all.Succeeded, all.FailureReason);
        Assert.Equal(2, all.Signatures.Count);

        var single = await verifier.VerifyAsync(message, label: "gateway");
        Assert.True(single.Succeeded, single.FailureReason);
        Assert.Equal("gateway", Assert.Single(single.Signatures).Label);
    }
}
