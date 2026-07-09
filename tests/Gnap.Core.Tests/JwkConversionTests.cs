using System.Security.Cryptography;
using System.Text;
using Gnap.Core;
using Gnap.Core.Keys;
using Xunit;

namespace Gnap.Core.Tests;

public class JwkConversionTests
{
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("gnap phase 1 test payload");

    [Theory]
    [InlineData(256, "P-256")]
    [InlineData(384, "P-384")]
    [InlineData(521, "P-521")]
    public void EcRoundtrip_PreservesKey(int keySize, string expectedCurve)
    {
        using var original = ECDsa.Create(keySize switch
        {
            256 => ECCurve.NamedCurves.nistP256,
            384 => ECCurve.NamedCurves.nistP384,
            _ => ECCurve.NamedCurves.nistP521,
        });

        var jwk = JsonWebKey.FromECDsa(original, includePrivateKey: true);
        Assert.Equal("EC", jwk.Kty);
        Assert.Equal(expectedCurve, jwk.Crv);
        Assert.True(jwk.HasPrivateKey);

        using var restored = jwk.ToECDsa();
        var signature = restored.SignData(Payload, HashAlgorithmName.SHA256);
        Assert.True(original.VerifyData(Payload, signature, HashAlgorithmName.SHA256));

        Assert.Equal(jwk.ComputeThumbprint(), JsonWebKey.FromECDsa(restored, includePrivateKey: true).ComputeThumbprint());
    }

    [Fact]
    public void RsaRoundtrip_PreservesKey()
    {
        using var original = RSA.Create(2048);
        var jwk = JsonWebKey.FromRsa(original, includePrivateKey: true, keyId: "rsa-1");

        using var restored = jwk.ToRsa();
        var signature = restored.SignData(Payload, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);
        Assert.True(original.VerifyData(Payload, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pss));
    }

    [Fact]
    public void Ed25519Roundtrip_PreservesKey()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        var signingAlgorithm = Gnap.HttpMessageSignatures.SignatureAlgorithm.Ed25519(null, privateKey);
        var signature = signingAlgorithm.Sign(Payload);

        // Derive the public key through BouncyCastle, then round-trip it via JWK.
        var publicKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(privateKey)
            .GeneratePublicKey().GetEncoded();
        var jwk = JsonWebKey.FromEd25519(publicKey, privateKey, keyId: "ed-1");

        Assert.Equal(publicKey, jwk.GetEd25519PublicKey());
        Assert.Equal(privateKey, jwk.GetEd25519PrivateKey());
        Assert.True(jwk.ToSignatureAlgorithm().Verify(Payload, signature));
    }

    [Theory]
    [InlineData(256, "ecdsa-p256-sha256")]
    [InlineData(384, "ecdsa-p384-sha384")]
    public void EcSignatureAlgorithm_SignsAndVerifies(int keySize, string expectedName)
    {
        using var key = ECDsa.Create(keySize == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384);
        var jwk = JsonWebKey.FromECDsa(key, includePrivateKey: true);

        var algorithm = jwk.ToSignatureAlgorithm();
        Assert.Equal(expectedName, algorithm.Name);

        var signature = algorithm.Sign(Payload);
        Assert.True(jwk.ToPublicKey().ToSignatureAlgorithm().Verify(Payload, signature));
    }

    [Theory]
    [InlineData("PS512", "rsa-pss-sha512")]
    [InlineData("RS256", "rsa-v1_5-sha256")]
    [InlineData(null, "rsa-pss-sha512")]
    public void RsaSignatureAlgorithm_FollowsJwkAlg(string? alg, string expectedName)
    {
        using var key = RSA.Create(2048);
        var jwk = JsonWebKey.FromRsa(key, includePrivateKey: true);
        jwk.Alg = alg;

        var algorithm = jwk.ToSignatureAlgorithm();
        Assert.Equal(expectedName, algorithm.Name);
        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
    }

    [Fact]
    public void P521SignatureAlgorithm_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        var jwk = JsonWebKey.FromECDsa(key, includePrivateKey: true);
        Assert.Throws<GnapException>(() => jwk.ToSignatureAlgorithm());
    }

    [Fact]
    public void MismatchedAlg_IsRejected()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var jwk = JsonWebKey.FromECDsa(key, includePrivateKey: true);
        jwk.Alg = "ES384";
        Assert.Throws<GnapException>(() => jwk.ToSignatureAlgorithm());
    }

    [Fact]
    public void ToPublicKey_StripsPrivateMaterial()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKey.FromRsa(rsa, includePrivateKey: true, keyId: "rsa-1");
        var publicJwk = jwk.ToPublicKey();

        Assert.False(publicJwk.HasPrivateKey);
        Assert.Null(publicJwk.D);
        Assert.Null(publicJwk.P);
        Assert.Null(publicJwk.Q);
        Assert.Equal(jwk.N, publicJwk.N);
        Assert.Equal("rsa-1", publicJwk.Kid);
        Assert.Equal(jwk.ComputeThumbprint(), publicJwk.ComputeThumbprint());
    }

    [Fact]
    public void WrongKeyType_Throws()
    {
        var jwk = new JsonWebKey { Kty = "RSA", N = "AQAB", E = "AQAB" };
        Assert.Throws<GnapException>(() => jwk.ToECDsa());
        Assert.Throws<GnapException>(() => jwk.GetEd25519PublicKey());
    }

    [Fact]
    public void InvalidBase64Url_Throws()
    {
        var jwk = new JsonWebKey { Kty = "RSA", N = "not base64url!!", E = "AQAB" };
        Assert.Throws<GnapException>(() => jwk.ToRsa());
    }
}
