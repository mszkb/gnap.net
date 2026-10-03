using System.Text.Json;
using System.Text.Json.Serialization;

namespace Gnap.Client.Discovery;

/// <summary>
/// The discovery document of a GNAP AS (RFC 9635 Section 9), returned for an
/// HTTP <c>OPTIONS</c> request to the grant endpoint. The same shape (plus
/// RS-facing members kept in <see cref="AdditionalFields"/>) is served at
/// <c>/.well-known/gnap-as-rs</c> (RFC 9767 Section 3.1).
/// </summary>
public sealed class AuthorizationServerMetadata
{
    /// <summary>The grant endpoint URI. Required.</summary>
    [JsonPropertyName("grant_request_endpoint")]
    public string? GrantRequestEndpoint { get; set; }

    /// <summary>The supported interaction start modes.</summary>
    [JsonPropertyName("interaction_start_modes_supported")]
    public IList<string>? InteractionStartModesSupported { get; set; }

    /// <summary>The supported interaction finish methods.</summary>
    [JsonPropertyName("interaction_finish_methods_supported")]
    public IList<string>? InteractionFinishMethodsSupported { get; set; }

    /// <summary>The supported key proofing methods.</summary>
    [JsonPropertyName("key_proofs_supported")]
    public IList<string>? KeyProofsSupported { get; set; }

    /// <summary>The supported subject identifier formats.</summary>
    [JsonPropertyName("sub_id_formats_supported")]
    public IList<string>? SubIdFormatsSupported { get; set; }

    /// <summary>The supported assertion formats.</summary>
    [JsonPropertyName("assertion_formats_supported")]
    public IList<string>? AssertionFormatsSupported { get; set; }

    /// <summary>Whether the AS supports rotating the key bound to an access token.</summary>
    [JsonPropertyName("key_rotation_supported")]
    public bool? KeyRotationSupported { get; set; }

    /// <summary>Extension members, e.g. the RS-facing endpoints of RFC 9767.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }

    /// <summary>Whether the AS advertises the given interaction start mode.</summary>
    public bool SupportsStartMode(string mode) => InteractionStartModesSupported?.Contains(mode) is true;

    /// <summary>Whether the AS advertises the given interaction finish method.</summary>
    public bool SupportsFinishMethod(string method) => InteractionFinishMethodsSupported?.Contains(method) is true;
}
