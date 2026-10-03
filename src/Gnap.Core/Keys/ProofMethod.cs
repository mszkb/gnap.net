using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;
using Gnap.HttpMessageSignatures;

namespace Gnap.Core.Keys;

/// <summary>
/// A key proofing method (RFC 9635 Section 7.3), sent either as a bare method
/// name string or as an object with a <c>method</c> member plus method-specific
/// parameters (for example <c>alg</c> and <c>content-digest-alg</c> for <c>httpsig</c>).
/// </summary>
[JsonConverter(typeof(ProofMethodConverter))]
public sealed class ProofMethod
{
    /// <summary>Creates a proof method reference.</summary>
    public ProofMethod(string method)
    {
        ArgumentException.ThrowIfNullOrEmpty(method);
        Method = method;
    }

    /// <summary>The registered key proofing method name, e.g. <c>httpsig</c>.</summary>
    public string Method { get; }

    /// <summary>Method-specific parameters when the proof was sent in object form.</summary>
    public IDictionary<string, JsonElement>? Parameters { get; set; }

    /// <summary>Returns a method-specific string parameter, or <see langword="null"/>.</summary>
    public string? GetParameter(string name) =>
        Parameters is not null && Parameters.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    /// <summary>
    /// Creates an object-form <c>httpsig</c> proof method (RFC 9635 Section 7.3.1)
    /// that pins the HTTP signature algorithm and the <c>Content-Digest</c> algorithm.
    /// </summary>
    /// <param name="algorithm">The RFC 9421 algorithm name, e.g. <c>ecdsa-p256-sha256</c>.</param>
    /// <param name="contentDigestAlgorithm">The digest algorithm protecting message content.</param>
    public static ProofMethod ForHttpSig(string algorithm, ContentDigestAlgorithm contentDigestAlgorithm = ContentDigestAlgorithm.Sha256)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        return new ProofMethod(Methods.HttpSig)
        {
            Parameters = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
            {
                [HttpSigParameters.Alg] = JsonHelpers.StringElement(algorithm),
                [HttpSigParameters.ContentDigestAlg] = JsonHelpers.StringElement(GetContentDigestAlgorithmName(contentDigestAlgorithm)),
            },
        };
    }

    /// <summary>
    /// The RFC 9421 signature algorithm pinned by an object-form <c>httpsig</c>
    /// proof (its <c>alg</c> parameter), or <see langword="null"/> when the proof
    /// was sent as a plain string and the algorithm follows from the key.
    /// </summary>
    [JsonIgnore]
    public string? HttpSigAlgorithm => Method == Methods.HttpSig ? GetParameter(HttpSigParameters.Alg) : null;

    /// <summary>
    /// The <c>Content-Digest</c> algorithm pinned by an object-form <c>httpsig</c>
    /// proof (its <c>content-digest-alg</c> parameter), or <see langword="null"/>
    /// when none is pinned.
    /// </summary>
    /// <exception cref="GnapException">The parameter names an unsupported digest algorithm.</exception>
    public ContentDigestAlgorithm? GetContentDigestAlgorithm()
    {
        if (Method != Methods.HttpSig || GetParameter(HttpSigParameters.ContentDigestAlg) is not { } name)
        {
            return null;
        }

        return name switch
        {
            "sha-256" => ContentDigestAlgorithm.Sha256,
            "sha-512" => ContentDigestAlgorithm.Sha512,
            _ => throw new GnapException($"Unsupported content-digest-alg '{name}'."),
        };
    }

    internal static string GetContentDigestAlgorithmName(ContentDigestAlgorithm algorithm) => algorithm switch
    {
        ContentDigestAlgorithm.Sha256 => "sha-256",
        ContentDigestAlgorithm.Sha512 => "sha-512",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    /// <summary>The parameter names of the object form of the <c>httpsig</c> method (RFC 9635 Section 7.3.1).</summary>
    public static class HttpSigParameters
    {
        /// <summary>The HTTP signature algorithm from the RFC 9421 registry.</summary>
        public const string Alg = "alg";

        /// <summary>The algorithm used for the <c>Content-Digest</c> field.</summary>
        public const string ContentDigestAlg = "content-digest-alg";
    }

    /// <summary>The registered proofing method names of RFC 9635.</summary>
    public static class Methods
    {
        /// <summary>HTTP message signatures (RFC 9421).</summary>
        public const string HttpSig = "httpsig";

        /// <summary>Mutual TLS certificate verification.</summary>
        public const string Mtls = "mtls";

        /// <summary>Detached JWS signature header.</summary>
        public const string Jwsd = "jwsd";

        /// <summary>Attached JWS payload.</summary>
        public const string Jws = "jws";
    }
}
