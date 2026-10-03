using Gnap.Core.Keys;
using Gnap.HttpMessageSignatures;

namespace Gnap.Core.Proofing;

/// <summary>
/// The <c>httpsig</c> key proofing method (RFC 9635 Section 7.3.1): signs
/// outgoing requests with an RFC 9421 HTTP message signature covering
/// <c>@method</c>, <c>@target-uri</c>, <c>content-digest</c> for messages with
/// content and <c>authorization</c> when an access token is presented, carrying
/// the required <c>created</c>, <c>nonce</c> and <c>tag="gnap"</c> parameters.
/// </summary>
public sealed class HttpSigKeyProofer : IKeyProofer
{
    private readonly SignatureAlgorithm _algorithm;
    private readonly string? _keyId;

    /// <summary>Creates a proofer from an algorithm with private key material.</summary>
    /// <param name="algorithm">The signing algorithm bound to the client instance's key.</param>
    /// <param name="keyId">The <c>keyid</c> to advertise; for JWKs this must be the <c>kid</c>.</param>
    public HttpSigKeyProofer(SignatureAlgorithm algorithm, string? keyId = null)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        if (!algorithm.CanSign)
        {
            throw new ArgumentException("The algorithm has no private key material and cannot create proofs.", nameof(algorithm));
        }

        _algorithm = algorithm;
        _keyId = keyId;
    }

    /// <summary>
    /// Creates a proofer from a JWK with private key material. The signature's
    /// <c>keyid</c> is the JWK's <c>kid</c> and the algorithm is derived from the
    /// key, as Section 7.3.1 requires.
    /// </summary>
    /// <exception cref="GnapException">The JWK cannot be mapped to a signature algorithm.</exception>
    public static HttpSigKeyProofer FromJwk(JsonWebKey jwk)
    {
        ArgumentNullException.ThrowIfNull(jwk);
        return new HttpSigKeyProofer(jwk.ToSignatureAlgorithm(), jwk.Kid);
    }

    /// <inheritdoc />
    public string Method => ProofMethod.Methods.HttpSig;

    /// <summary>The signature label. Defaults to <c>sig1</c>.</summary>
    public string Label { get; init; } = "sig1";

    /// <summary>The digest algorithm for the <c>Content-Digest</c> field. Defaults to <c>sha-256</c>.</summary>
    public ContentDigestAlgorithm ContentDigestAlgorithm { get; init; } = ContentDigestAlgorithm.Sha256;

    /// <summary>The byte length of the random <c>nonce</c>. Defaults to 16.</summary>
    public int NonceLength { get; init; } = 16;

    /// <summary>Components to cover in addition to the ones mandated by GNAP.</summary>
    public IReadOnlyList<SignatureComponent> AdditionalComponents { get; init; } = [];

    /// <summary>The clock used for the <c>created</c> parameter; overridable for tests.</summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// The object-form <c>httpsig</c> proof method describing this proofer's
    /// signature and content digest algorithms (RFC 9635 Section 7.3.1), for use
    /// in the <c>key.proof</c> field the client presents to the AS.
    /// </summary>
    public ProofMethod ToProofMethod() => ProofMethod.ForHttpSig(_algorithm.Name, ContentDigestAlgorithm);

    /// <inheritdoc />
    public async Task AddProofAsync(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var components = new List<SignatureComponent>
        {
            SignatureComponent.Method,
            SignatureComponent.TargetUri,
        };

        if (request.Content is not null)
        {
            var content = await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            if (!request.Content.Headers.Contains("Content-Digest"))
            {
                request.Content.Headers.TryAddWithoutValidation(
                    "Content-Digest",
                    ContentDigest.CreateHeaderValue(content, ContentDigestAlgorithm));
            }

            components.Add(SignatureComponent.ContentDigest);
        }

        if (request.Headers.Contains("Authorization"))
        {
            components.Add(SignatureComponent.Field("authorization"));
        }

        foreach (var component in AdditionalComponents)
        {
            if (!components.Contains(component))
            {
                components.Add(component);
            }
        }

        var signer = new HttpMessageSigner(_algorithm)
        {
            Label = Label,
            KeyId = _keyId,
            CoveredComponents = components,
            IncludeCreated = true,
            // Section 7.3.1: the alg parameter MUST NOT be included; the verifier
            // derives the algorithm from the key material.
            IncludeAlgorithm = false,
            NonceLength = NonceLength,
            Tag = GnapConstants.HttpSignatureTag,
            TimeProvider = TimeProvider,
        };

        signer.Sign(request);
    }
}
