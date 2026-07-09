using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gnap.HttpMessageSignatures;

namespace Gnap.Core.Keys;

public sealed partial class JsonWebKey
{
    /// <summary>Well-known <c>kty</c> values.</summary>
    public static class KeyTypes
    {
        /// <summary>Elliptic curve keys.</summary>
        public const string Ec = "EC";

        /// <summary>Octet key pairs (Ed25519).</summary>
        public const string Okp = "OKP";

        /// <summary>RSA keys.</summary>
        public const string Rsa = "RSA";

        /// <summary>Symmetric keys.</summary>
        public const string Oct = "oct";
    }

    /// <summary>Creates an EC JWK from an <see cref="ECDsa"/> key (curves P-256, P-384 and P-521).</summary>
    /// <exception cref="GnapException">The key uses an unsupported curve.</exception>
    public static JsonWebKey FromECDsa(ECDsa key, bool includePrivateKey = false, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(key);
        var parameters = key.ExportParameters(includePrivateKey);
        var (crv, alg) = key.KeySize switch
        {
            256 => ("P-256", "ES256"),
            384 => ("P-384", "ES384"),
            521 => ("P-521", "ES512"),
            _ => throw new GnapException($"Unsupported EC key size {key.KeySize}."),
        };

        return new JsonWebKey
        {
            Kty = KeyTypes.Ec,
            Crv = crv,
            Alg = alg,
            Kid = keyId,
            X = Base64Url.EncodeToString(parameters.Q.X),
            Y = Base64Url.EncodeToString(parameters.Q.Y),
            D = includePrivateKey && parameters.D is not null ? Base64Url.EncodeToString(parameters.D) : null,
        };
    }

    /// <summary>Creates an RSA JWK from an <see cref="RSA"/> key.</summary>
    public static JsonWebKey FromRsa(RSA key, bool includePrivateKey = false, string? keyId = null, string algorithm = "PS512")
    {
        ArgumentNullException.ThrowIfNull(key);
        var parameters = key.ExportParameters(includePrivateKey);
        return new JsonWebKey
        {
            Kty = KeyTypes.Rsa,
            Alg = algorithm,
            Kid = keyId,
            N = Base64Url.EncodeToString(parameters.Modulus),
            E = Base64Url.EncodeToString(parameters.Exponent),
            D = includePrivateKey ? Base64Url.EncodeToString(parameters.D) : null,
            P = includePrivateKey ? Base64Url.EncodeToString(parameters.P) : null,
            Q = includePrivateKey ? Base64Url.EncodeToString(parameters.Q) : null,
            DP = includePrivateKey ? Base64Url.EncodeToString(parameters.DP) : null,
            DQ = includePrivateKey ? Base64Url.EncodeToString(parameters.DQ) : null,
            QI = includePrivateKey ? Base64Url.EncodeToString(parameters.InverseQ) : null,
        };
    }

    /// <summary>Creates an OKP JWK from raw Ed25519 key bytes (32-byte public key, optional 32-byte private seed).</summary>
    public static JsonWebKey FromEd25519(byte[] publicKey, byte[]? privateKey = null, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        return new JsonWebKey
        {
            Kty = KeyTypes.Okp,
            Crv = "Ed25519",
            Alg = "EdDSA",
            Kid = keyId,
            X = Base64Url.EncodeToString(publicKey),
            D = privateKey is null ? null : Base64Url.EncodeToString(privateKey),
        };
    }

    /// <summary>Converts an EC JWK into an <see cref="ECDsa"/> instance owned by the caller.</summary>
    /// <exception cref="GnapException">The key is not a complete EC key on a supported curve.</exception>
    public ECDsa ToECDsa()
    {
        RequireKty(KeyTypes.Ec);
        var (curve, size) = Crv switch
        {
            "P-256" => (ECCurve.NamedCurves.nistP256, 32),
            "P-384" => (ECCurve.NamedCurves.nistP384, 48),
            "P-521" => (ECCurve.NamedCurves.nistP521, 66),
            _ => throw new GnapException($"Unsupported EC curve '{Crv}'."),
        };

        var parameters = new ECParameters
        {
            Curve = curve,
            Q = new ECPoint
            {
                X = DecodeFixed(X, "x", size),
                Y = DecodeFixed(Y, "y", size),
            },
            D = D is null ? null : DecodeFixed(D, "d", size),
        };

        var key = ECDsa.Create();
        try
        {
            key.ImportParameters(parameters);
            return key;
        }
        catch (CryptographicException e)
        {
            key.Dispose();
            throw new GnapException("The EC JWK does not contain a valid key.", e);
        }
    }

    /// <summary>Converts an RSA JWK into an <see cref="RSA"/> instance owned by the caller.</summary>
    /// <exception cref="GnapException">The key is not a complete RSA key.</exception>
    public RSA ToRsa()
    {
        RequireKty(KeyTypes.Rsa);
        var parameters = new RSAParameters
        {
            Modulus = Decode(N, "n"),
            Exponent = Decode(E, "e"),
        };

        if (D is not null)
        {
            parameters.D = Decode(D, "d");
            parameters.P = Decode(P, "p");
            parameters.Q = Decode(Q, "q");
            parameters.DP = Decode(DP, "dp");
            parameters.DQ = Decode(DQ, "dq");
            parameters.InverseQ = Decode(QI, "qi");
        }

        var key = RSA.Create();
        try
        {
            key.ImportParameters(parameters);
            return key;
        }
        catch (CryptographicException e)
        {
            key.Dispose();
            throw new GnapException("The RSA JWK does not contain a valid key.", e);
        }
    }

    /// <summary>Returns the raw 32-byte Ed25519 public key of an OKP JWK.</summary>
    /// <exception cref="GnapException">The key is not an Ed25519 OKP key.</exception>
    public byte[] GetEd25519PublicKey()
    {
        RequireKty(KeyTypes.Okp);
        if (Crv != "Ed25519")
        {
            throw new GnapException($"Unsupported OKP curve '{Crv}'.");
        }

        return DecodeFixed(X, "x", 32);
    }

    /// <summary>Returns the raw 32-byte Ed25519 private key of an OKP JWK, or <see langword="null"/> if absent.</summary>
    /// <exception cref="GnapException">The key is not an Ed25519 OKP key.</exception>
    public byte[]? GetEd25519PrivateKey()
    {
        RequireKty(KeyTypes.Okp);
        if (Crv != "Ed25519")
        {
            throw new GnapException($"Unsupported OKP curve '{Crv}'.");
        }

        return D is null ? null : DecodeFixed(D, "d", 32);
    }

    /// <summary>
    /// Binds this key to the RFC 9421 signature algorithm implied by its type, curve
    /// and <c>alg</c> member. EC and OKP keys map directly; RSA keys use the JWS
    /// algorithm (<c>PS512</c> when absent, per the httpsig defaults used by GNAP).
    /// </summary>
    /// <exception cref="GnapException">The key type or algorithm has no RFC 9421 counterpart.</exception>
    public SignatureAlgorithm ToSignatureAlgorithm() => Kty switch
    {
        KeyTypes.Ec => Crv switch
        {
            "P-256" => Ensure("ES256", SignatureAlgorithm.EcdsaP256Sha256(ToECDsa())),
            "P-384" => Ensure("ES384", SignatureAlgorithm.EcdsaP384Sha384(ToECDsa())),
            _ => throw new GnapException($"EC curve '{Crv}' has no registered HTTP signature algorithm."),
        },
        KeyTypes.Okp when Crv == "Ed25519" => Ensure("EdDSA", SignatureAlgorithm.Ed25519(GetEd25519PublicKey(), GetEd25519PrivateKey())),
        KeyTypes.Rsa => Alg switch
        {
            null or "PS512" => SignatureAlgorithm.RsaPssSha512(ToRsa()),
            "RS256" => SignatureAlgorithm.RsaV15Sha256(ToRsa()),
            _ => throw new GnapException($"RSA algorithm '{Alg}' has no supported HTTP signature algorithm."),
        },
        _ => throw new GnapException($"Key type '{Kty}' cannot be used for HTTP message signatures."),
    };

    /// <summary>
    /// Computes the RFC 7638 thumbprint (SHA-256 over the canonical required members,
    /// base64url encoded). OKP keys use the required members of RFC 8037.
    /// </summary>
    /// <exception cref="GnapException">A required member is missing or the key type is unknown.</exception>
    public string ComputeThumbprint()
    {
        var members = Kty switch
        {
            KeyTypes.Ec => new (string Name, string Value)[]
            {
                ("crv", Require(Crv, "crv")),
                ("kty", KeyTypes.Ec),
                ("x", Require(X, "x")),
                ("y", Require(Y, "y")),
            },
            KeyTypes.Okp =>
            [
                ("crv", Require(Crv, "crv")),
                ("kty", KeyTypes.Okp),
                ("x", Require(X, "x")),
            ],
            KeyTypes.Rsa =>
            [
                ("e", Require(E, "e")),
                ("kty", KeyTypes.Rsa),
                ("n", Require(N, "n")),
            ],
            KeyTypes.Oct =>
            [
                ("k", Require(K, "k")),
                ("kty", KeyTypes.Oct),
            ],
            _ => throw new GnapException($"Cannot compute a thumbprint for key type '{Kty}'."),
        };

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            foreach (var (name, value) in members)
            {
                writer.WriteString(name, value);
            }

            writer.WriteEndObject();
        }

        return Base64Url.EncodeToString(SHA256.HashData(stream.ToArray()));
    }

    private SignatureAlgorithm Ensure(string expectedAlg, SignatureAlgorithm algorithm) =>
        Alg is null || Alg == expectedAlg
            ? algorithm
            : throw new GnapException($"The JWK alg '{Alg}' does not match the key's algorithm '{expectedAlg}'.");

    private void RequireKty(string expected)
    {
        if (Kty != expected)
        {
            throw new GnapException($"Expected a JWK of type '{expected}' but found '{Kty}'.");
        }
    }

    private static string Require(string? value, string member) =>
        value ?? throw new GnapException($"The JWK is missing the required member '{member}'.");

    private static byte[] Decode(string? value, string member)
    {
        try
        {
            return Base64Url.DecodeFromChars(Require(value, member));
        }
        catch (FormatException e)
        {
            throw new GnapException($"The JWK member '{member}' is not valid base64url.", e);
        }
    }

    private static byte[] DecodeFixed(string? value, string member, int size)
    {
        var bytes = Decode(value, member);
        if (bytes.Length == size)
        {
            return bytes;
        }

        if (bytes.Length > size)
        {
            throw new GnapException($"The JWK member '{member}' is longer than the {size} bytes allowed by the curve.");
        }

        // Left-pad values whose leading zero bytes were dropped by a lenient encoder.
        var padded = new byte[size];
        bytes.CopyTo(padded, size - bytes.Length);
        return padded;
    }
}
