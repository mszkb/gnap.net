using System.Text.Json.Serialization;
using Gnap.Core.Keys;

namespace Gnap.Core.Models;

/// <summary>The registered access token flags of RFC 9635.</summary>
public static class AccessTokenFlags
{
    /// <summary>The token is a bearer token, not bound to a key.</summary>
    public const string Bearer = "bearer";

    /// <summary>The token keeps working after rotation or grant modification (response only).</summary>
    public const string Durable = "durable";
}

/// <summary>
/// A request for a single access token (RFC 9635 Section 2.1). Multiple tokens
/// are requested by sending several of these, each with a unique label.
/// </summary>
public sealed class AccessTokenRequest
{
    /// <summary>The rights of access being requested. Required.</summary>
    [JsonPropertyName("access")]
    public IList<AccessRight>? Access { get; set; }

    /// <summary>The client-chosen name for the resulting token. Required when requesting multiple tokens.</summary>
    [JsonPropertyName("label")]
    public string? Label { get; set; }

    /// <summary>Requested token attributes, e.g. <see cref="AccessTokenFlags.Bearer"/>.</summary>
    [JsonPropertyName("flags")]
    public IList<string>? Flags { get; set; }

    /// <summary>Whether the <c>bearer</c> flag is requested.</summary>
    [JsonIgnore]
    public bool IsBearer => Flags?.Contains(AccessTokenFlags.Bearer) is true;
}

/// <summary>An issued access token (RFC 9635 Section 3.2.1).</summary>
public sealed class AccessTokenResponse
{
    /// <summary>The token value (token68 character set). Required.</summary>
    [JsonPropertyName("value")]
    public string? Value { get; set; }

    /// <summary>The label from the corresponding token request.</summary>
    [JsonPropertyName("label")]
    public string? Label { get; set; }

    /// <summary>Access information for the token management API, if management is offered.</summary>
    [JsonPropertyName("manage")]
    public TokenManagement? Manage { get; set; }

    /// <summary>The rights of access actually associated with the token. Required.</summary>
    [JsonPropertyName("access")]
    public IList<AccessRight>? Access { get; set; }

    /// <summary>Seconds until the token expires.</summary>
    [JsonPropertyName("expires_in")]
    public long? ExpiresIn { get; set; }

    /// <summary>The key the token is bound to, when different from the client instance's key.</summary>
    [JsonPropertyName("key")]
    public GnapKey? Key { get; set; }

    /// <summary>Token attributes, e.g. <see cref="AccessTokenFlags.Bearer"/> or <see cref="AccessTokenFlags.Durable"/>.</summary>
    [JsonPropertyName("flags")]
    public IList<string>? Flags { get; set; }

    /// <summary>Whether the token is a bearer token.</summary>
    [JsonIgnore]
    public bool IsBearer => Flags?.Contains(AccessTokenFlags.Bearer) is true;

    /// <summary>Whether the token is flagged as durable across rotation and modification.</summary>
    [JsonIgnore]
    public bool IsDurable => Flags?.Contains(AccessTokenFlags.Durable) is true;

    /// <summary>
    /// Whether the token is bound to the key the client instance presented in its
    /// request (neither a bearer token nor bound to a different key).
    /// </summary>
    [JsonIgnore]
    public bool IsBoundToClientKey => !IsBearer && Key is null;
}

/// <summary>The token management descriptor of an issued access token.</summary>
public sealed class TokenManagement
{
    /// <summary>The absolute URI of the token management API. Required.</summary>
    [JsonPropertyName("uri")]
    public string? Uri { get; set; }

    /// <summary>The key-bound token management access token. Required.</summary>
    [JsonPropertyName("access_token")]
    public AccessTokenResponse? AccessToken { get; set; }
}
