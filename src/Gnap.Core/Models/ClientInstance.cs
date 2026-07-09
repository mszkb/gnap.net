using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;
using Gnap.Core.Keys;

namespace Gnap.Core.Models;

/// <summary>
/// The <c>client</c> field of a grant request (RFC 9635 Section 2.3): either an
/// instance identifier string or an object carrying the client instance's key
/// and display information.
/// </summary>
[JsonConverter(typeof(ClientInstanceConverter))]
public sealed class ClientInstance
{
    /// <summary>The instance identifier when the client is passed by reference.</summary>
    public string? Reference { get; set; }

    /// <summary>The client instance's key. Required when passed by value.</summary>
    public GnapKey? Key { get; set; }

    /// <summary>An identifier for the client software, interpreted by the AS.</summary>
    public string? ClassId { get; set; }

    /// <summary>Information the AS may display to the RO during interaction.</summary>
    public ClientDisplay? Display { get; set; }

    /// <summary>Extension fields from the GNAP Client Instance Fields registry.</summary>
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }

    /// <summary>Whether this client is an instance identifier reference.</summary>
    [JsonIgnore]
    public bool IsReference => Reference is not null;

    /// <summary>Creates a client identified by an instance identifier.</summary>
    public static ClientInstance ForReference(string instanceId)
    {
        ArgumentException.ThrowIfNullOrEmpty(instanceId);
        return new ClientInstance { Reference = instanceId };
    }
}

/// <summary>Displayable client instance information (RFC 9635 Section 2.3.2).</summary>
public sealed class ClientDisplay
{
    /// <summary>The display name of the client software.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>An absolute URI with user-facing information about the client software.</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }

    /// <summary>An absolute URI (or data: URI) of a display image for the client software.</summary>
    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; set; }
}
