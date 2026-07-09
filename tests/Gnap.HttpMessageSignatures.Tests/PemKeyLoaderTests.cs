using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Importing the RFC 9421 example keys from their PEM encodings.</summary>
public class PemKeyLoaderTests
{
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("payload");

    [Fact]
    public void RsaPkcs1Key_LoadsAndSigns()
    {
        using var key = PemKeyLoader.LoadRsa(Rfc9421TestVectors.RsaTestKeyPem);
        var algorithm = SignatureAlgorithm.RsaV15Sha256(key);

        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
    }

    [Fact]
    public void RsaPssOidPkcs8Key_LoadsAndSigns()
    {
        // .NET's RSA.ImportFromPem rejects PKCS#8 keys carrying the RSASSA-PSS
        // algorithm identifier; the loader unwraps them manually.
        using var key = PemKeyLoader.LoadRsa(Rfc9421TestVectors.RsaPssTestKeyPem);
        var algorithm = SignatureAlgorithm.RsaPssSha512(key);

        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
    }

    [Fact]
    public void RsaPublicKeyOnly_LoadsForVerification()
    {
        const string publicOnly = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
            +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
            oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
            gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
            Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
            aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
            2wIDAQAB
            -----END PUBLIC KEY-----
            """;
        using var signingKey = PemKeyLoader.LoadRsa(Rfc9421TestVectors.RsaPssTestKeyPem);
        using var verifyKey = PemKeyLoader.LoadRsa(publicOnly);

        var signature = SignatureAlgorithm.RsaPssSha512(signingKey).Sign(Payload);

        Assert.True(SignatureAlgorithm.RsaPssSha512(verifyKey).Verify(Payload, signature));
    }

    [Fact]
    public void EccP256Key_LoadsAndSigns()
    {
        using var key = PemKeyLoader.LoadEcdsa(Rfc9421TestVectors.EccP256TestKeyPem);
        var algorithm = SignatureAlgorithm.EcdsaP256Sha256(key);

        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
    }

    [Fact]
    public void Ed25519Key_LoadsBothHalves()
    {
        var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(Rfc9421TestVectors.Ed25519TestKeyPem);

        Assert.NotNull(publicKey);
        Assert.NotNull(privateKey);
        Assert.Equal(32, publicKey!.Length);
        Assert.Equal(32, privateKey!.Length);

        var algorithm = SignatureAlgorithm.Ed25519(publicKey, privateKey);
        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
    }

    [Fact]
    public void Ed25519PrivateKey_DerivesMatchingPublicKey()
    {
        var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(Rfc9421TestVectors.Ed25519TestKeyPem);

        var signOnly = SignatureAlgorithm.Ed25519(publicKey: null, privateKey: privateKey);
        var verifyOnly = SignatureAlgorithm.Ed25519(publicKey, privateKey: null);

        Assert.False(verifyOnly.CanSign);
        Assert.True(verifyOnly.Verify(Payload, signOnly.Sign(Payload)));
    }

    [Fact]
    public void EcdsaKeySizeMismatch_IsRejected()
    {
        using var key = PemKeyLoader.LoadEcdsa(Rfc9421TestVectors.EccP256TestKeyPem);

        Assert.Throws<ArgumentException>(() => SignatureAlgorithm.EcdsaP384Sha384(key));
    }
}
