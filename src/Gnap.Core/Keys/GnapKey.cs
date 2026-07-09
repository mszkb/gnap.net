using System.Text.Json.Serialization;
using Gnap.Core.Json;
using Gnap.HttpMessageSignatures;

namespace Gnap.Core.Keys;

/// <summary>
/// Key material in a GNAP message (RFC 9635 Section 7.1): either an opaque key
/// reference string or an object carrying the public key in one supported format
/// together with its proofing method.
/// </summary>
[JsonConverter(typeof(GnapKeyConverter))]
public sealed class GnapKey
{
    /// <summary>The opaque key reference when the key is passed by reference.</summary>
    public string? Reference { get; set; }

    /// <summary>The proofing method bound to this key. Required when passed by value.</summary>
    public ProofMethod? Proof { get; set; }

    /// <summary>The public key as a JSON Web Key.</summary>
    public JsonWebKey? Jwk { get; set; }

    /// <summary>The PEM-serialized certificate (headers and internal whitespace optional).</summary>
    public string? Cert { get; set; }

    /// <summary>The base64url SHA-256 certificate thumbprint (<c>cert#S256</c>).</summary>
    public string? CertS256 { get; set; }

    /// <summary>Whether this key is a reference rather than a value.</summary>
    [JsonIgnore]
    public bool IsReference => Reference is not null;

    /// <summary>Creates a key passed by reference.</summary>
    public static GnapKey ForReference(string reference)
    {
        ArgumentException.ThrowIfNullOrEmpty(reference);
        return new GnapKey { Reference = reference };
    }

    /// <summary>Creates an <c>httpsig</c>-proofed key from a JWK, stripped to its public part.</summary>
    public static GnapKey ForHttpSig(JsonWebKey jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        return new GnapKey
        {
            Proof = new ProofMethod(ProofMethod.Methods.HttpSig),
            Jwk = jwk.ToPublicKey(),
        };
    }

    /// <summary>
    /// Binds the JWK of this key to its RFC 9421 signature algorithm for verification.
    /// </summary>
    /// <exception cref="GnapException">The key is a reference or carries no JWK.</exception>
    public SignatureAlgorithm ToSignatureAlgorithm() =>
        Jwk?.ToSignatureAlgorithm()
        ?? throw new GnapException(IsReference
            ? "A key reference must be resolved to key material before use."
            : "The key does not contain a JWK; other key formats must be resolved by the caller.");
}
