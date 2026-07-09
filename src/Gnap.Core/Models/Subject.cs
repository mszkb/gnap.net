using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.Core.Json;

namespace Gnap.Core.Models;

/// <summary>The subject identifier formats of RFC 9493 referenced by GNAP.</summary>
public static class SubjectIdentifierFormats
{
    /// <summary>An account URI (<c>acct:</c>).</summary>
    public const string Account = "account";

    /// <summary>A set of aliases for the same subject.</summary>
    public const string Aliases = "aliases";

    /// <summary>A decentralized identifier URL.</summary>
    public const string Did = "did";

    /// <summary>An email address.</summary>
    public const string Email = "email";

    /// <summary>An issuer/subject pair.</summary>
    public const string IssSub = "iss_sub";

    /// <summary>An opaque identifier.</summary>
    public const string Opaque = "opaque";

    /// <summary>A telephone number.</summary>
    public const string PhoneNumber = "phone_number";

    /// <summary>A URI.</summary>
    public const string Uri = "uri";
}

/// <summary>The assertion formats registered by RFC 9635.</summary>
public static class AssertionFormats
{
    /// <summary>An OpenID Connect ID Token in JWT compact form.</summary>
    public const string IdToken = "id_token";

    /// <summary>A SAML 2 assertion as unpadded base64url.</summary>
    public const string Saml2 = "saml2";
}

/// <summary>
/// A subject identifier as defined by RFC 9493. The typed properties cover the
/// registered formats; any further format-specific members are preserved in
/// <see cref="AdditionalFields"/>.
/// </summary>
public sealed class SubjectIdentifier
{
    /// <summary>The identifier format, e.g. <see cref="SubjectIdentifierFormats.Opaque"/>. Required.</summary>
    [JsonPropertyName("format")]
    public string? Format { get; set; }

    /// <summary>The opaque identifier value (<c>opaque</c> format).</summary>
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    /// <summary>The email address (<c>email</c> format).</summary>
    [JsonPropertyName("email")]
    public string? Email { get; set; }

    /// <summary>The telephone number (<c>phone_number</c> format).</summary>
    [JsonPropertyName("phone_number")]
    public string? PhoneNumber { get; set; }

    /// <summary>The issuer (<c>iss_sub</c> format).</summary>
    [JsonPropertyName("iss")]
    public string? Iss { get; set; }

    /// <summary>The subject at the issuer (<c>iss_sub</c> format).</summary>
    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    /// <summary>The URI (<c>uri</c> and <c>account</c> formats).</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }

    /// <summary>The DID URL (<c>did</c> format).</summary>
    [JsonPropertyName("url")]
    public string? Url { get; set; }

    /// <summary>Further format-specific members, e.g. <c>identifiers</c> of the <c>aliases</c> format.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>An assertion about a subject, as exchanged in GNAP messages.</summary>
public sealed class SubjectAssertion
{
    /// <summary>The assertion format, e.g. <see cref="AssertionFormats.IdToken"/>. Required.</summary>
    [JsonPropertyName("format")]
    public string? Format { get; set; }

    /// <summary>The assertion value as its JSON string serialization. Required.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }
}

/// <summary>The <c>subject</c> field of a grant request (RFC 9635 Section 2.2).</summary>
public sealed class SubjectRequest
{
    /// <summary>The requested subject identifier formats.</summary>
    [JsonPropertyName("sub_id_formats")]
    public IList<string>? SubIdFormats { get; set; }

    /// <summary>The requested assertion formats.</summary>
    [JsonPropertyName("assertion_formats")]
    public IList<string>? AssertionFormats { get; set; }

    /// <summary>Identifiers of the subject the request is about; all must identify the same subject.</summary>
    [JsonPropertyName("sub_ids")]
    public IList<SubjectIdentifier>? SubIds { get; set; }

    /// <summary>Extension fields from the GNAP Subject Information Request Fields registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>The <c>subject</c> field of a grant response (RFC 9635 Section 3.4).</summary>
public sealed class SubjectResponse
{
    /// <summary>Subject identifiers for the RO.</summary>
    [JsonPropertyName("sub_ids")]
    public IList<SubjectIdentifier>? SubIds { get; set; }

    /// <summary>Assertions about the RO.</summary>
    [JsonPropertyName("assertions")]
    public IList<SubjectAssertion>? Assertions { get; set; }

    /// <summary>When the identified account was last updated (RFC 3339).</summary>
    [JsonPropertyName("updated_at")]
    public DateTimeOffset? UpdatedAt { get; set; }

    /// <summary>Extension fields from the GNAP Subject Information Response Fields registry.</summary>
    [JsonExtensionData]
    public IDictionary<string, JsonElement>? AdditionalFields { get; set; }
}

/// <summary>
/// The <c>user</c> field of a grant request (RFC 9635 Section 2.4): either an
/// opaque user reference string or identifiers and assertions for the end user.
/// </summary>
[JsonConverter(typeof(RequestUserConverter))]
public sealed class RequestUser
{
    /// <summary>The opaque user reference when the user is passed by reference.</summary>
    public string? Reference { get; set; }

    /// <summary>Subject identifiers for the end user.</summary>
    public IList<SubjectIdentifier>? SubIds { get; set; }

    /// <summary>Assertions about the end user.</summary>
    public IList<SubjectAssertion>? Assertions { get; set; }

    /// <summary>Whether this user is a reference rather than an object.</summary>
    [JsonIgnore]
    public bool IsReference => Reference is not null;

    /// <summary>Creates a user identified by an opaque reference.</summary>
    public static RequestUser ForReference(string reference)
    {
        ArgumentException.ThrowIfNullOrEmpty(reference);
        return new RequestUser { Reference = reference };
    }
}
