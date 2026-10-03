using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// The BouncyCastle-backed RSA fallback that <see cref="PemKeyLoader"/> uses for valid
/// keys the platform rejects. Windows CNG refuses the RFC 9421 <c>test-key-rsa</c>
/// because its primes (1088 and 960 bits) are not half the modulus length; these
/// tests exercise the fallback directly so it is covered on every platform.
/// </summary>
public class BouncyCastleRsaTests
{
    private static readonly byte[] Payload = Encoding.UTF8.GetBytes("payload");

    private static byte[] RsaTestKeyPkcs1()
    {
        var pem = Rfc9421TestVectors.RsaTestKeyPem;
        var tail = pem[pem.IndexOf("-----BEGIN RSA PRIVATE KEY-----", StringComparison.Ordinal)..];
        var fields = PemEncoding.Find(tail);
        return Convert.FromBase64String(tail[fields.Base64Data]);
    }

    private static RSA RsaTestPublicKey()
    {
        var rsa = RSA.Create();
        var pem = Rfc9421TestVectors.RsaTestKeyPem;
        var publicBlock = pem[..pem.IndexOf("-----BEGIN RSA PRIVATE KEY-----", StringComparison.Ordinal)];
        rsa.ImportFromPem(publicBlock);
        return rsa;
    }

    [Fact]
    public void RfcTestKeyRsa_HasUnbalancedPrimes()
    {
        using var key = BouncyCastleRsa.TryCreate(RsaTestKeyPkcs1());

        Assert.NotNull(key);
        Assert.Equal(2048, key!.KeySize);
        var parameters = key.ExportParameters(includePrivateParameters: true);
        Assert.NotEqual(parameters.P!.Length, parameters.Q!.Length);
    }

    [Theory]
    [InlineData("SHA256", "pkcs1")]
    [InlineData("SHA256", "pss")]
    [InlineData("SHA384", "pss")]
    [InlineData("SHA512", "pkcs1")]
    [InlineData("SHA512", "pss")]
    public void Signatures_InteroperateWithPlatformRsa(string hashName, string paddingName)
    {
        var hash = new HashAlgorithmName(hashName);
        var padding = paddingName == "pss" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using var fallback = BouncyCastleRsa.TryCreate(RsaTestKeyPkcs1())!;
        using var platformPublic = RsaTestPublicKey();

        var signature = fallback.SignData(Payload, hash, padding);

        Assert.True(platformPublic.VerifyData(Payload, signature, hash, padding));
        Assert.True(fallback.VerifyData(Payload, signature, hash, padding));
        Assert.False(fallback.VerifyData(Encoding.UTF8.GetBytes("tampered"), signature, hash, padding));
    }

    [Fact]
    public void Pkcs1Signature_MatchesPlatformDeterministically()
    {
        // PKCS#1 v1.5 signatures are deterministic, so both providers must agree byte for byte.
        using var fallback = BouncyCastleRsa.TryCreate(RsaTestKeyPkcs1())!;
        using var platform = PemKeyLoader.LoadRsa(Rfc9421TestVectors.RsaTestKeyPem);

        Assert.Equal(
            platform.SignData(Payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            fallback.SignData(Payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void WorksThroughSignatureAlgorithm()
    {
        using var fallback = BouncyCastleRsa.TryCreate(RsaTestKeyPkcs1())!;
        var algorithm = SignatureAlgorithm.RsaV15Sha256(fallback);

        Assert.True(algorithm.Verify(Payload, algorithm.Sign(Payload)));
        Assert.False(algorithm.Verify(Payload, new byte[256]));
        Assert.False(algorithm.Verify(Payload, new byte[3]));
    }

    [Fact]
    public void InconsistentKey_IsRejected()
    {
        var der = RsaTestKeyPkcs1();
        // Flip a bit in the last byte (inside the CRT coefficient): n = p·q still holds,
        // but the CRT values no longer agree with d.
        der[^1] ^= 0x01;

        Assert.Null(BouncyCastleRsa.TryCreate(der));
    }

    [Fact]
    public void Garbage_IsRejected()
    {
        Assert.Null(BouncyCastleRsa.TryCreate([0x30, 0x03, 0x02, 0x01, 0x00]));
        Assert.Null(BouncyCastleRsa.TryCreate([0x01, 0x02]));
    }

    [Fact]
    public void UnsupportedHashOrMismatchedLength_Throws()
    {
        using var fallback = BouncyCastleRsa.TryCreate(RsaTestKeyPkcs1())!;

        Assert.Throws<CryptographicException>(() => fallback.SignHash(new byte[20], HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
        Assert.Throws<CryptographicException>(() => fallback.SignHash(new byte[20], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        Assert.Throws<NotSupportedException>(() => fallback.ImportParameters(default));
    }
}
