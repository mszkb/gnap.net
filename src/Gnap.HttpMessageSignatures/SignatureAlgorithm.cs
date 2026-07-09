using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// A signature algorithm from the HTTP Signature Algorithms registry
/// (RFC 9421 Section 3.3), bound to concrete key material.
/// </summary>
public abstract class SignatureAlgorithm
{
    /// <summary>The registered algorithm name, e.g. <c>ed25519</c> or <c>rsa-pss-sha512</c>.</summary>
    public abstract string Name { get; }

    /// <summary>Whether the bound key material can create signatures (private/secret key present).</summary>
    public abstract bool CanSign { get; }

    /// <summary>Signs the signature base bytes.</summary>
    /// <exception cref="InvalidOperationException">No private key material is available.</exception>
    public abstract byte[] Sign(ReadOnlySpan<byte> data);

    /// <summary>Verifies a signature over the signature base bytes.</summary>
    public abstract bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);

    /// <summary>RSASSA-PSS with SHA-512 (<c>rsa-pss-sha512</c>). The RSA key is owned by the caller.</summary>
    public static SignatureAlgorithm RsaPssSha512(RSA key) =>
        new RsaAlgorithm("rsa-pss-sha512", key, HashAlgorithmName.SHA512, RSASignaturePadding.Pss);

    /// <summary>RSASSA-PKCS1-v1_5 with SHA-256 (<c>rsa-v1_5-sha256</c>). The RSA key is owned by the caller.</summary>
    public static SignatureAlgorithm RsaV15Sha256(RSA key) =>
        new RsaAlgorithm("rsa-v1_5-sha256", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    /// <summary>ECDSA over P-256 with SHA-256 (<c>ecdsa-p256-sha256</c>). The key is owned by the caller.</summary>
    public static SignatureAlgorithm EcdsaP256Sha256(ECDsa key) =>
        new EcdsaAlgorithm("ecdsa-p256-sha256", key, HashAlgorithmName.SHA256, expectedKeySize: 256);

    /// <summary>ECDSA over P-384 with SHA-384 (<c>ecdsa-p384-sha384</c>). The key is owned by the caller.</summary>
    public static SignatureAlgorithm EcdsaP384Sha384(ECDsa key) =>
        new EcdsaAlgorithm("ecdsa-p384-sha384", key, HashAlgorithmName.SHA384, expectedKeySize: 384);

    /// <summary>HMAC with SHA-256 (<c>hmac-sha256</c>) over a shared secret.</summary>
    public static SignatureAlgorithm HmacSha256(byte[] sharedSecret) => new HmacAlgorithm(sharedSecret);

    /// <summary>
    /// EdDSA over edwards25519 (<c>ed25519</c>) from raw 32-byte keys. Pass the
    /// public key for verification and/or the private key for signing.
    /// </summary>
    public static SignatureAlgorithm Ed25519(byte[]? publicKey, byte[]? privateKey = null) =>
        new Ed25519Algorithm(publicKey, privateKey);

    private sealed class RsaAlgorithm(string name, RSA key, HashAlgorithmName hash, RSASignaturePadding padding)
        : SignatureAlgorithm
    {
        public override string Name => name;

        public override bool CanSign => true;

        public override byte[] Sign(ReadOnlySpan<byte> data) => key.SignData(data.ToArray(), hash, padding);

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
            key.VerifyData(data.ToArray(), signature.ToArray(), hash, padding);
    }

    private sealed class EcdsaAlgorithm : SignatureAlgorithm
    {
        private readonly ECDsa _key;
        private readonly HashAlgorithmName _hash;

        public EcdsaAlgorithm(string name, ECDsa key, HashAlgorithmName hash, int expectedKeySize)
        {
            if (key.KeySize != expectedKeySize)
            {
                throw new ArgumentException($"{name} requires a {expectedKeySize}-bit key but the key has {key.KeySize} bits.", nameof(key));
            }

            Name = name;
            _key = key;
            _hash = hash;
        }

        public override string Name { get; }

        public override bool CanSign => true;

        // .NET produces and consumes the IEEE P1363 fixed-size r||s concatenation
        // by default, which is the wire format required by RFC 9421.
        public override byte[] Sign(ReadOnlySpan<byte> data) => _key.SignData(data.ToArray(), _hash);

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
            _key.VerifyData(data.ToArray(), signature.ToArray(), _hash);
    }

    private sealed class HmacAlgorithm(byte[] sharedSecret) : SignatureAlgorithm
    {
        private readonly byte[] _secret = (byte[])sharedSecret.Clone();

        public override string Name => "hmac-sha256";

        public override bool CanSign => true;

        public override byte[] Sign(ReadOnlySpan<byte> data) => HMACSHA256.HashData(_secret, data.ToArray());

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature) =>
            CryptographicOperations.FixedTimeEquals(Sign(data), signature);
    }

    private sealed class Ed25519Algorithm : SignatureAlgorithm
    {
        private readonly Ed25519PublicKeyParameters? _publicKey;
        private readonly Ed25519PrivateKeyParameters? _privateKey;

        public Ed25519Algorithm(byte[]? publicKey, byte[]? privateKey)
        {
            if (publicKey is null && privateKey is null)
            {
                throw new ArgumentException("At least one of publicKey and privateKey is required.");
            }

            _privateKey = privateKey is null ? null : new Ed25519PrivateKeyParameters(privateKey);
            _publicKey = publicKey is null
                ? _privateKey!.GeneratePublicKey()
                : new Ed25519PublicKeyParameters(publicKey);
        }

        public override string Name => "ed25519";

        public override bool CanSign => _privateKey is not null;

        public override byte[] Sign(ReadOnlySpan<byte> data)
        {
            if (_privateKey is null)
            {
                throw new InvalidOperationException("No Ed25519 private key is available for signing.");
            }

            var signer = new Ed25519Signer();
            signer.Init(forSigning: true, _privateKey);
            signer.BlockUpdate(data.ToArray(), 0, data.Length);
            return signer.GenerateSignature();
        }

        public override bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            var signer = new Ed25519Signer();
            signer.Init(forSigning: false, _publicKey);
            signer.BlockUpdate(data.ToArray(), 0, data.Length);
            return signer.VerifySignature(signature.ToArray());
        }
    }
}
