using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>
/// A grant request sent to the AS's grant endpoint (RFC 9635 Section 2).
/// </summary>
public sealed class GrantRequest
{
    /// <summary>
    /// The requested access tokens. A single element serializes as an object, more
    /// than one as an array (each then requires a unique label), per Section 2.1.
    /// </summary>
    [JsonPropertyName("access_token")]
    [JsonConverter(typeof(OneOrManyConverter<AccessTokenRequest>))]
    public IList<AccessTokenRequest>? AccessToken { get; set; }

    /// <summary>The subject information being requested.</summary>
    [JsonPropertyName("subject")]
    public SubjectRequest? Subject { get; set; }

    /// <summary>The client instance making the request. Required.</summary>
    [JsonPropertyName("client")]
    public ClientInstance? Client { get; set; }

    /// <summary>The end user as known to the client instance.</summary>
    [JsonPropertyName("user")]
    public RequestUser? User { get; set; }

    /// <summary>The interaction capabilities of the client instance.</summary>
    [JsonPropertyName("interact")]
    public InteractRequest? Interact { get; set; }

    /// <summary>Extension fields from the GNAP Grant Request Parameters registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>
/// The content of a continuation request after a finished interaction
/// (RFC 9635 Section 5.1). Polling continuations send no content at all.
/// </summary>
public sealed class ContinueRequest
{
    /// <summary>The one-time-use interaction reference from the finish callback. Required.</summary>
    [JsonPropertyName("interact_ref")]
    public string? InteractRef { get; set; }
}
