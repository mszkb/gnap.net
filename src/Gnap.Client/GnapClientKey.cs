using Gnap.Core;
using Gnap.Core.Keys;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;

namespace Gnap.Client;

/// <summary>
/// A key held by the client instance: the private signing key used for
/// <c>httpsig</c> key proofs (RFC 9635 Section 7.3.1) together with the public
/// <see cref="GnapKey"/> the client presents to the AS, either by value or by
/// reference (Section 7.1).
/// </summary>
public sealed class GnapClientKey
{
    /// <summary>Creates a client key from a signing algorithm and the key to present.</summary>
    /// <param name="algorithm">The signing algorithm with private key material.</param>
    /// <param name="presentedKey">The public key (or key reference) sent to the AS.</param>
    /// <param name="keyId">The <c>keyid</c> signature parameter; for JWKs the <c>kid</c>.</param>
    public GnapClientKey(SignatureAlgorithm algorithm, GnapKey presentedKey, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(presentedKey);
        if (!algorithm.CanSign)
        {
            throw new ArgumentException("The algorithm has no private key material and cannot create proofs.", nameof(algorithm));
        }

        Algorithm = algorithm;
        PresentedKey = presentedKey;
        KeyId = keyId;
        ContentDigestAlgorithm = presentedKey.Proof?.GetContentDigestAlgorithm() ?? ContentDigestAlgorithm.Sha256;
    }

    /// <summary>The signing algorithm bound to the private key.</summary>
    public SignatureAlgorithm Algorithm { get; }

    /// <summary>The key as presented to the AS: a public JWK with its proof method, or a reference.</summary>
    public GnapKey PresentedKey { get; }

    /// <summary>The <c>keyid</c> signature parameter.</summary>
    public string? KeyId { get; }

    /// <summary>The digest algorithm for <c>Content-Digest</c>; follows a pinned <c>content-digest-alg</c>.</summary>
    public ContentDigestAlgorithm ContentDigestAlgorithm { get; }

    /// <summary>
    /// Creates a client key from a private JWK, presented by value as an
    /// <c>httpsig</c> key. With <paramref name="pinnedContentDigestAlgorithm"/> the
    /// object form of the proof method is used, pinning <c>alg</c> and
    /// <c>content-digest-alg</c>.
    /// </summary>
    /// <exception cref="GnapException">The JWK has no private key or cannot be mapped to a signature algorithm.</exception>
    public static GnapClientKey FromJwk(JsonWebKey privateJwk, ContentDigestAlgorithm? pinnedContentDigestAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(privateJwk);
        if (!privateJwk.HasPrivateKey)
        {
            throw new GnapException("A client key requires a JWK with private key material.");
        }

        var presented = pinnedContentDigestAlgorithm is { } digest
            ? GnapKey.ForHttpSig(privateJwk, digest)
            : GnapKey.ForHttpSig(privateJwk);
        return new GnapClientKey(privateJwk.ToSignatureAlgorithm(), presented, privateJwk.Kid);
    }

    /// <summary>
    /// Returns a copy of this key that is presented to the AS by an opaque
    /// reference (RFC 9635 Section 7.1.1) instead of by value; requests are still
    /// signed with the private key.
    /// </summary>
    public GnapClientKey WithReference(string keyReference) =>
        new(Algorithm, GnapKey.ForReference(keyReference), KeyId);

    /// <summary>Creates an <c>httpsig</c> proofer that signs requests with this key.</summary>
    /// <param name="timeProvider">The clock for the <c>created</c> parameter.</param>
    /// <param name="label">The signature label.</param>
    /// <param name="additionalComponents">Components to cover beyond the GNAP-mandated ones.</param>
    public HttpSigKeyProofer CreateProofer(
        TimeProvider? timeProvider = null,
        string label = "sig1",
        IReadOnlyList<SignatureComponent>? additionalComponents = null) =>
        new(Algorithm, KeyId)
        {
            Label = label,
            ContentDigestAlgorithm = ContentDigestAlgorithm,
            AdditionalComponents = additionalComponents ?? [],
            TimeProvider = timeProvider ?? TimeProvider.System,
        };
}
