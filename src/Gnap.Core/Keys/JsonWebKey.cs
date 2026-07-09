using System.Text.Json.Serialization;

namespace Gnap.Core.Keys;

/// <summary>
/// A JSON Web Key (RFC 7517) restricted to the key types used by GNAP:
/// elliptic curve (<c>EC</c>), octet key pair (<c>OKP</c>, Ed25519) and RSA.
/// All binary members are base64url strings, exactly as they appear on the wire.
/// </summary>
public sealed partial class JsonWebKey
{
    /// <summary>The key type (<c>EC</c>, <c>OKP</c>, <c>RSA</c> or <c>oct</c>).</summary>
    [JsonPropertyName("kty")]
    public string? Kty { get; set; }

    /// <summary>The curve name for EC and OKP keys, e.g. <c>P-256</c> or <c>Ed25519</c>.</summary>
    [JsonPropertyName("crv")]
    public string? Crv { get; set; }

    /// <summary>The EC x coordinate or the OKP public key.</summary>
    [JsonPropertyName("x")]
    public string? X { get; set; }

    /// <summary>The EC y coordinate.</summary>
    [JsonPropertyName("y")]
    public string? Y { get; set; }

    /// <summary>The EC or OKP private key, or the RSA private exponent.</summary>
    [JsonPropertyName("d")]
    public string? D { get; set; }

    /// <summary>The RSA modulus.</summary>
    [JsonPropertyName("n")]
    public string? N { get; set; }

    /// <summary>The RSA public exponent.</summary>
    [JsonPropertyName("e")]
    public string? E { get; set; }

    /// <summary>The RSA first prime factor.</summary>
    [JsonPropertyName("p")]
    public string? P { get; set; }

    /// <summary>The RSA second prime factor.</summary>
    [JsonPropertyName("q")]
    public string? Q { get; set; }

    /// <summary>The RSA first factor CRT exponent.</summary>
    [JsonPropertyName("dp")]
    public string? DP { get; set; }

    /// <summary>The RSA second factor CRT exponent.</summary>
    [JsonPropertyName("dq")]
    public string? DQ { get; set; }

    /// <summary>The RSA first CRT coefficient.</summary>
    [JsonPropertyName("qi")]
    public string? QI { get; set; }

    /// <summary>The symmetric key value for <c>oct</c> keys.</summary>
    [JsonPropertyName("k")]
    public string? K { get; set; }

    /// <summary>The key identifier. GNAP requires this on keys passed by value.</summary>
    [JsonPropertyName("kid")]
    public string? Kid { get; set; }

    /// <summary>The JWS algorithm intended for this key. GNAP requires this on keys passed by value.</summary>
    [JsonPropertyName("alg")]
    public string? Alg { get; set; }

    /// <summary>The intended key use (<c>sig</c> or <c>enc</c>).</summary>
    [JsonPropertyName("use")]
    public string? Use { get; set; }

    /// <summary>The allowed key operations.</summary>
    [JsonPropertyName("key_ops")]
    public IList<string>? KeyOps { get; set; }

    /// <summary>The X.509 certificate chain (base64, not base64url).</summary>
    [JsonPropertyName("x5c")]
    public IList<string>? X5c { get; set; }

    /// <summary>Whether the key carries private key material.</summary>
    [JsonIgnore]
    public bool HasPrivateKey => D is not null || K is not null;

    /// <summary>Returns a copy without any private or symmetric key material.</summary>
    public JsonWebKey ToPublicKey() => new()
    {
        Kty = Kty,
        Crv = Crv,
        X = X,
        Y = Y,
        N = N,
        E = E,
        Kid = Kid,
        Alg = Alg,
        Use = Use,
        KeyOps = KeyOps?.ToList(),
        X5c = X5c?.ToList(),
    };
}
