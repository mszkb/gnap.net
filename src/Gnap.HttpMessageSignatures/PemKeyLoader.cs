using System.Formats.Asn1;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// Imports signing and verification keys from PEM text, including formats that
/// <see cref="RSA.ImportFromPem"/> rejects (PKCS#8 keys with the RSASSA-PSS
/// algorithm identifier, as used by the RFC 9421 test keys) and Ed25519 keys,
/// which .NET 8 has no built-in type for.
/// </summary>
public static class PemKeyLoader
{
    private const string RsaPssOid = "1.2.840.113549.1.1.10";

    /// <summary>Loads an RSA key pair or public key from PEM. The caller owns (disposes) the key.</summary>
    /// <exception cref="CryptographicException">No usable RSA key was found.</exception>
    /// <remarks>
    /// Private keys whose primes are not exactly half the modulus length (valid, but
    /// rejected by Windows CNG, e.g. the RFC 9421 <c>test-key-rsa</c>) are loaded into
    /// a BouncyCastle-backed <see cref="RSA"/> that supports signing and verification.
    /// </remarks>
    public static RSA LoadRsa(string pem)
    {
        foreach (var (label, der) in EnumeratePemBlocks(pem))
        {
            switch (label)
            {
                case "RSA PRIVATE KEY":
                    return ImportRsaPrivateKey(der);
                case "PRIVATE KEY":
                    return ImportRsaPrivateKey(UnwrapPkcs8(der));
            }
        }

        var rsa = RSA.Create();
        try
        {
            foreach (var (label, der) in EnumeratePemBlocks(pem))
            {
                switch (label)
                {
                    case "RSA PUBLIC KEY":
                        rsa.ImportRSAPublicKey(der, out _);
                        return rsa;
                    case "PUBLIC KEY":
                        rsa.ImportSubjectPublicKeyInfo(der, out _);
                        return rsa;
                }
            }

            throw new CryptographicException("The PEM text contains no RSA key.");
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Imports a PKCS#1 RSAPrivateKey into the platform provider, falling back to
    /// <see cref="BouncyCastleRsa"/> for consistent keys the platform rejects.
    /// </summary>
    internal static RSA ImportRsaPrivateKey(byte[] pkcs1Der)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportRSAPrivateKey(pkcs1Der, out _);
            return rsa;
        }
        catch (CryptographicException)
        {
            rsa.Dispose();
            if (BouncyCastleRsa.TryCreate(pkcs1Der) is { } fallback)
            {
                return fallback;
            }

            throw;
        }
    }

    /// <summary>Loads an ECDSA key pair or public key from PEM. The caller owns (disposes) the key.</summary>
    /// <exception cref="CryptographicException">No usable EC key was found.</exception>
    public static ECDsa LoadEcdsa(string pem)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            foreach (var (label, der) in EnumeratePemBlocks(pem))
            {
                switch (label)
                {
                    case "EC PRIVATE KEY":
                        ecdsa.ImportECPrivateKey(der, out _);
                        return ecdsa;
                    case "PRIVATE KEY":
                        ecdsa.ImportPkcs8PrivateKey(der, out _);
                        return ecdsa;
                }
            }

            foreach (var (label, der) in EnumeratePemBlocks(pem))
            {
                if (label == "PUBLIC KEY")
                {
                    ecdsa.ImportSubjectPublicKeyInfo(der, out _);
                    return ecdsa;
                }
            }

            throw new CryptographicException("The PEM text contains no EC key.");
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Loads an Ed25519 key from PEM ("PRIVATE KEY" and/or "PUBLIC KEY" blocks) and
    /// returns the raw 32-byte keys for <see cref="SignatureAlgorithm.Ed25519"/>.
    /// </summary>
    /// <exception cref="CryptographicException">No Ed25519 key block was found.</exception>
    public static (byte[]? PublicKey, byte[]? PrivateKey) LoadEd25519(string pem)
    {
        byte[]? publicKey = null;
        byte[]? privateKey = null;
        foreach (var (label, der) in EnumeratePemBlocks(pem))
        {
            switch (label)
            {
                case "PRIVATE KEY" when PrivateKeyFactory.CreateKey(der) is Ed25519PrivateKeyParameters priv:
                    privateKey = priv.GetEncoded();
                    publicKey ??= priv.GeneratePublicKey().GetEncoded();
                    break;
                case "PUBLIC KEY" when PublicKeyFactory.CreateKey(der) is Ed25519PublicKeyParameters pub:
                    publicKey = pub.GetEncoded();
                    break;
            }
        }

        if (publicKey is null && privateKey is null)
        {
            throw new CryptographicException("The PEM text contains no Ed25519 key.");
        }

        return (publicKey, privateKey);
    }

    /// <summary>
    /// Extracts the inner PKCS#1 RSAPrivateKey from a PKCS#8 PrivateKeyInfo,
    /// accepting both the rsaEncryption and the RSASSA-PSS algorithm identifiers.
    /// </summary>
    private static byte[] UnwrapPkcs8(byte[] pkcs8Der)
    {
        var reader = new AsnReader(pkcs8Der, AsnEncodingRules.BER);
        var privateKeyInfo = reader.ReadSequence();
        privateKeyInfo.ReadInteger();
        var algorithm = privateKeyInfo.ReadSequence();
        var oid = algorithm.ReadObjectIdentifier();
        if (oid is not ("1.2.840.113549.1.1.1" or RsaPssOid))
        {
            throw new CryptographicException($"The PKCS#8 key algorithm {oid} is not an RSA key.");
        }

        return privateKeyInfo.ReadOctetString();
    }

    private static IEnumerable<(string Label, byte[] Der)> EnumeratePemBlocks(string pem)
    {
        var remaining = pem.AsMemory();
        while (PemEncoding.TryFind(remaining.Span, out var fields))
        {
            var label = remaining.Span[fields.Label].ToString();
            var der = new byte[fields.DecodedDataLength];
            if (!Convert.TryFromBase64Chars(remaining.Span[fields.Base64Data], der, out _))
            {
                throw new CryptographicException("Invalid base64 in PEM block.");
            }

            yield return (label, der);
            remaining = remaining[fields.Location.End..];
        }
    }
}
