using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Construction rules and registered names of <see cref="SignatureAlgorithm"/>.</summary>
public class SignatureAlgorithmTests
{
    private static readonly byte[] Data = Encoding.UTF8.GetBytes("signature base");

    [Theory]
    [InlineData("rsa-pss-sha512")]
    [InlineData("rsa-v1_5-sha256")]
    [InlineData("ecdsa-p256-sha256")]
    [InlineData("ecdsa-p384-sha384")]
    [InlineData("hmac-sha256")]
    [InlineData("ed25519")]
    public void Name_IsTheRegisteredAlgorithmName(string name)
    {
        var algorithm = RoundtripTests.CreateFreshKey(name);

        Assert.Equal(name, algorithm.Name);
        Assert.True(algorithm.CanSign);
    }

    [Fact]
    public void EcdsaWithWrongCurve_IsRejected()
    {
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var error = Assert.Throws<ArgumentException>("key", () => SignatureAlgorithm.EcdsaP256Sha256(p384));

        Assert.StartsWith("ecdsa-p256-sha256 requires a 256-bit key but the key has 384 bits.", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ed25519WithoutAnyKey_IsRejected()
    {
        var error = Assert.Throws<ArgumentException>(() => SignatureAlgorithm.Ed25519(publicKey: null, privateKey: null));

        Assert.Equal("At least one of publicKey and privateKey is required.", error.Message);
    }

    [Fact]
    public void Ed25519PublicKeyOnly_VerifiesButCannotSign()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        var signer = SignatureAlgorithm.Ed25519(publicKey: null, privateKey);
        var publicKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(privateKey).GeneratePublicKey().GetEncoded();
        var verifier = SignatureAlgorithm.Ed25519(publicKey);

        Assert.False(verifier.CanSign);
        Assert.True(verifier.Verify(Data, signer.Sign(Data)));
        var error = Assert.Throws<InvalidOperationException>(() => verifier.Sign(Data));
        Assert.Equal("No Ed25519 private key is available for signing.", error.Message);
    }
}
