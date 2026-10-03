using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// An <see cref="RSA"/> private key backed by BouncyCastle, used for valid keys
/// the platform provider cannot import. Windows CNG (and .NET's key blob
/// conversion there) requires both primes to be exactly half the modulus
/// length; keys with unbalanced primes, such as the RFC 9421 B.1.1
/// <c>test-key-rsa</c> (1088- and 960-bit primes), are rejected with
/// "ASN1 corrupted data" although they are mathematically sound. Supports
/// signing and verification with PKCS#1 v1.5 and PSS (salt length = hash length,
/// MGF1 with the same hash, as <see cref="RSASignaturePadding.Pss"/>).
/// </summary>
internal sealed class BouncyCastleRsa : RSA
{
    private readonly RsaPrivateCrtKeyParameters _privateKey;
    private readonly RsaKeyParameters _publicKey;

    private BouncyCastleRsa(RsaPrivateCrtKeyParameters privateKey)
    {
        _privateKey = privateKey;
        _publicKey = new RsaKeyParameters(false, privateKey.Modulus, privateKey.PublicExponent);
        KeySizeValue = privateKey.Modulus.BitLength;
        LegalKeySizesValue = [new KeySizes(512, 16384, 8)];
    }

    /// <summary>
    /// Creates a key from a PKCS#1 RSAPrivateKey, provided it is consistent
    /// (n = p·q and e·d ≡ 1 modulo λ(n) as checked by a sign/verify probe);
    /// returns <see langword="null"/> otherwise.
    /// </summary>
    public static BouncyCastleRsa? TryCreate(ReadOnlySpan<byte> pkcs1PrivateKey)
    {
        RsaPrivateKeyStructure structure;
        try
        {
            structure = RsaPrivateKeyStructure.GetInstance(Asn1Object.FromByteArray(pkcs1PrivateKey.ToArray()));
        }
        catch (Exception e) when (e is ArgumentException or IOException or InvalidCastException)
        {
            return null;
        }

        if (structure.Modulus.SignValue <= 0 ||
            !structure.Prime1.Multiply(structure.Prime2).Equals(structure.Modulus))
        {
            return null;
        }

        var parameters = new RsaPrivateCrtKeyParameters(
            structure.Modulus, structure.PublicExponent, structure.PrivateExponent,
            structure.Prime1, structure.Prime2, structure.Exponent1, structure.Exponent2, structure.Coefficient);

        // The CRT values must agree with the private exponent; a raw RSA round trip
        // with a non-trivial message detects mismatches (BouncyCastle's engine also
        // checks its own CRT result and throws on a fault).
        var probe = BigInteger.ValueOf(0x5EED);
        var probeBytes = probe.ToByteArrayUnsigned();
        var engine = new RsaBlindedEngine();
        engine.Init(true, parameters);
        try
        {
            var signed = new BigInteger(1, engine.ProcessBlock(probeBytes, 0, probeBytes.Length));
            if (!signed.ModPow(structure.PublicExponent, structure.Modulus).Equals(probe))
            {
                return null;
            }
        }
        catch (InvalidOperationException)
        {
            return null;
        }

        return new BouncyCastleRsa(parameters);
    }

    public override string SignatureAlgorithm => "RSA";

    public override RSAParameters ExportParameters(bool includePrivateParameters)
    {
        var result = new RSAParameters
        {
            Modulus = _privateKey.Modulus.ToByteArrayUnsigned(),
            Exponent = _privateKey.PublicExponent.ToByteArrayUnsigned(),
        };
        if (includePrivateParameters)
        {
            result.D = _privateKey.Exponent.ToByteArrayUnsigned();
            result.P = _privateKey.P.ToByteArrayUnsigned();
            result.Q = _privateKey.Q.ToByteArrayUnsigned();
            result.DP = _privateKey.DP.ToByteArrayUnsigned();
            result.DQ = _privateKey.DQ.ToByteArrayUnsigned();
            result.InverseQ = _privateKey.QInv.ToByteArrayUnsigned();
        }

        return result;
    }

    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException("This key is immutable; create a new RSA instance instead.");

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        var signer = CreateSigner(hashAlgorithm, padding, hash.Length);
        signer.Init(true, _privateKey);
        signer.BlockUpdate(hash, 0, hash.Length);
        return signer.GenerateSignature();
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(signature);
        var signer = CreateSigner(hashAlgorithm, padding, hash.Length);
        signer.Init(false, _publicKey);
        signer.BlockUpdate(hash, 0, hash.Length);
        try
        {
            return signer.VerifySignature(signature);
        }
        catch (DataLengthException)
        {
            return false;
        }
    }

    protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
    {
        using var hash = IncrementalHash.CreateHash(hashAlgorithm);
        hash.AppendData(data, offset, count);
        return hash.GetHashAndReset();
    }

    protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
    {
        using var hash = IncrementalHash.CreateHash(hashAlgorithm);
        var buffer = new byte[4096];
        int read;
        while ((read = data.Read(buffer, 0, buffer.Length)) > 0)
        {
            hash.AppendData(buffer, 0, read);
        }

        return hash.GetHashAndReset();
    }

    private static ISigner CreateSigner(HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, int hashLength)
    {
        ArgumentNullException.ThrowIfNull(padding);
        var (digest, oid) = hashAlgorithm.Name switch
        {
            "SHA256" => ((IDigest)new Sha256Digest(), NistObjectIdentifiers.IdSha256),
            "SHA384" => (new Sha384Digest(), NistObjectIdentifiers.IdSha384),
            "SHA512" => (new Sha512Digest(), NistObjectIdentifiers.IdSha512),
            _ => throw new CryptographicException($"Hash algorithm '{hashAlgorithm.Name}' is not supported."),
        };

        if (hashLength != digest.GetDigestSize())
        {
            throw new CryptographicException($"The hash length {hashLength} does not match {hashAlgorithm.Name}.");
        }

        if (padding == RSASignaturePadding.Pkcs1)
        {
            // NullDigest passes the precomputed hash through; the signer wraps it in a DigestInfo.
            return new RsaDigestSigner(new NullDigest(), oid);
        }

        if (padding == RSASignaturePadding.Pss)
        {
            return PssSigner.CreateRawSigner(new RsaBlindedEngine(), digest);
        }

        throw new CryptographicException($"RSA signature padding '{padding}' is not supported.");
    }
}
