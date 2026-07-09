using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>
/// One element of an <c>access</c> array (RFC 9635 Section 8): either an opaque
/// reference string known to the AS or a structured object describing rights of
/// access. API-specific fields beyond the common ones are kept in
/// <see cref="AdditionalFields"/>.
/// </summary>
[JsonConverter(typeof(AccessRightConverter))]
public sealed class AccessRight
{
    /// <summary>The reference string when the access right is passed by reference.</summary>
    public string? Reference { get; set; }

    /// <summary>The type of resource request; determines the semantics of the other fields.</summary>
    public string? Type { get; set; }

    /// <summary>The actions the client will take at the RS, e.g. <c>read</c>.</summary>
    public IList<string>? Actions { get; set; }

    /// <summary>The locations of the RS, typically URIs.</summary>
    public IList<string>? Locations { get; set; }

    /// <summary>The kinds of data available at the RS's API.</summary>
    public IList<string>? Datatypes { get; set; }

    /// <summary>An identifier for a specific resource at the RS.</summary>
    public string? Identifier { get; set; }

    /// <summary>The types or levels of privilege being requested.</summary>
    public IList<string>? Privileges { get; set; }

    /// <summary>API-specific fields defined by the <see cref="Type"/>.</summary>
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }

    /// <summary>Whether this access right is a reference rather than an object.</summary>
    [JsonIgnore]
    public bool IsReference => Reference is not null;

    /// <summary>Creates an access right passed by reference.</summary>
    public static AccessRight ForReference(string reference)
    {
        ArgumentException.ThrowIfNullOrEmpty(reference);
        return new AccessRight { Reference = reference };
    }
}
