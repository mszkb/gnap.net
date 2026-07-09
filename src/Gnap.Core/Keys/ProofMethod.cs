using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

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
