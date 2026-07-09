using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>
/// A grant response from the AS (RFC 9635 Section 3).
/// </summary>
public sealed class GrantResponse
{
    /// <summary>How the client instance can continue the grant request.</summary>
    [JsonPropertyName("continue")]
    public ContinueResponse? Continue { get; set; }

    /// <summary>The issued access tokens (an object for one, an array for several).</summary>
    [JsonPropertyName("access_token")]
    [JsonConverter(typeof(OneOrManyConverter<AccessTokenResponse>))]
    public IList<AccessTokenResponse>? AccessToken { get; set; }

    /// <summary>The interaction modes offered by the AS.</summary>
    [JsonPropertyName("interact")]
    public InteractResponse? Interact { get; set; }

    /// <summary>The released subject information.</summary>
    [JsonPropertyName("subject")]
    public SubjectResponse? Subject { get; set; }

    /// <summary>An instance identifier for the client to use in future requests.</summary>
    [JsonPropertyName("instance_id")]
    public string? InstanceId { get; set; }

    /// <summary>The error, when the request could not be completed.</summary>
    [JsonPropertyName("error")]
    public GnapError? Error { get; set; }

    /// <summary>Extension fields from the GNAP Grant Response Parameters registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>The <c>continue</c> field of a grant response (RFC 9635 Section 3.1).</summary>
public sealed class ContinueResponse
{
    /// <summary>The absolute continuation URI, used exactly as given. Required.</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }

    /// <summary>Seconds the client must wait before calling the continuation URI; five when absent.</summary>
    [JsonPropertyName("wait")]
    public int? Wait { get; set; }

    /// <summary>The key-bound continuation access token. Required.</summary>
    [JsonPropertyName("access_token")]
    public AccessTokenResponse? AccessToken { get; set; }

    /// <summary>The effective wait time, applying the five-second default of Section 3.1.</summary>
    [JsonIgnore]
    public TimeSpan EffectiveWait => TimeSpan.FromSeconds(Wait ?? 5);
}
