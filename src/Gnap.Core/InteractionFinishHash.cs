using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Gnap.Core;

/// <summary>
/// Computes and verifies the interaction finish hash of RFC 9635 Section 4.2.3:
/// the base64url-encoded hash of the client nonce, AS nonce, interaction reference
/// and grant endpoint URI, joined by single newlines.
/// </summary>
public static class InteractionFinishHash
{
    /// <summary>The default hash method used when the client did not request one.</summary>
    public const string DefaultHashMethod = "sha-256";

    /// <summary>
    /// Computes the finish hash. <paramref name="hashMethod"/> is a hash name string
    /// from the IANA Named Information Hash Algorithm Registry; <see langword="null"/>
    /// selects the <c>sha-256</c> default.
    /// </summary>
    /// <exception cref="GnapException">The hash method is unknown or unavailable on this platform.</exception>
    public static string Compute(
        string clientNonce,
        string asNonce,
        string interactRef,
        string grantEndpointUri,
        string? hashMethod = null)
    {
        ArgumentNullException.ThrowIfNull(clientNonce);
        ArgumentNullException.ThrowIfNull(asNonce);
        ArgumentNullException.ThrowIfNull(interactRef);
        ArgumentNullException.ThrowIfNull(grantEndpointUri);

        var hashBase = $"{clientNonce}\n{asNonce}\n{interactRef}\n{grantEndpointUri}";
        var input = Encoding.ASCII.GetBytes(hashBase);
        return Base64Url.EncodeToString(Hash(hashMethod ?? DefaultHashMethod, input));
    }

    /// <summary>
    /// Verifies a received finish hash in constant time against the locally
    /// computed value. Returns <see langword="false"/> for malformed input rather
    /// than throwing, so callers can treat any failure uniformly.
    /// </summary>
    public static bool Verify(
        string receivedHash,
        string clientNonce,
        string asNonce,
        string interactRef,
        string grantEndpointUri,
        string? hashMethod = null)
    {
        ArgumentNullException.ThrowIfNull(receivedHash);
        try
        {
            var expected = Compute(clientNonce, asNonce, interactRef, grantEndpointUri, hashMethod);
            return CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expected),
                Encoding.ASCII.GetBytes(receivedHash));
        }
        catch (GnapException)
        {
            return false;
        }
    }

    /// <summary>Whether the given hash method is supported on this platform.</summary>
    public static bool IsSupported(string hashMethod) => hashMethod switch
    {
        "sha-256" or "sha-384" or "sha-512" => true,
        "sha3-256" => SHA3_256.IsSupported,
        "sha3-384" => SHA3_384.IsSupported,
        "sha3-512" => SHA3_512.IsSupported,
        _ => false,
    };

    private static byte[] Hash(string hashMethod, byte[] input) => hashMethod switch
    {
        "sha-256" => SHA256.HashData(input),
        "sha-384" => SHA384.HashData(input),
        "sha-512" => SHA512.HashData(input),
        "sha3-256" when SHA3_256.IsSupported => SHA3_256.HashData(input),
        "sha3-384" when SHA3_384.IsSupported => SHA3_384.HashData(input),
        "sha3-512" when SHA3_512.IsSupported => SHA3_512.HashData(input),
        "sha3-256" or "sha3-384" or "sha3-512" =>
            throw new GnapException($"The hash method '{hashMethod}' is not supported on this platform."),
        _ => throw new GnapException($"Unknown hash method '{hashMethod}'."),
    };
}
