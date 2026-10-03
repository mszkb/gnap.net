using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.AspNetCore.AuthorizationServer.Stores;

/// <summary>
/// The server-side state of one issued access token. The token value and the
/// management token are kept only as SHA-256 hashes.
/// </summary>
public sealed class TokenRecord
{
    /// <summary>The token identifier (also the JWT <c>jti</c> for JWT tokens).</summary>
    public required string Id { get; set; }

    /// <summary>The grant the token was issued for.</summary>
    public required string GrantId { get; set; }

    /// <summary>The SHA-256 hash of the token value.</summary>
    public required string ValueHash { get; set; }

    /// <summary>The rights of access associated with the token.</summary>
    public IList<AccessRight> Access { get; set; } = [];

    /// <summary>The label from the token request, if any.</summary>
    public string? Label { get; set; }

    /// <summary>The key the token is bound to; <see langword="null"/> for a bearer token.</summary>
    public GnapKey? BoundKey { get; set; }

    /// <summary>The key that must sign token management requests (the client instance's key).</summary>
    public required GnapKey ManagementKey { get; set; }

    /// <summary>The identifier in the token management URI, when management is offered.</summary>
    public string? ManageId { get; set; }

    /// <summary>The SHA-256 hash of the token management access token.</summary>
    public string? ManageTokenHash { get; set; }

    /// <summary>When the token was issued.</summary>
    public DateTimeOffset IssuedAt { get; set; }

    /// <summary>When the token expires, if it does.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }

    /// <summary>Whether the token was revoked (explicitly, by rotation or with its grant).</summary>
    public bool Revoked { get; set; }

    /// <summary>The client instance identifier, if known.</summary>
    public string? InstanceId { get; set; }

    /// <summary>The resource owner the grant was approved for, if known.</summary>
    public string? ResourceOwner { get; set; }

    /// <summary>The issuer (grant endpoint URI) of the token.</summary>
    public string? Issuer { get; set; }

    /// <summary>Whether this is a bearer token.</summary>
    public bool IsBearer => BoundKey is null;

    /// <summary>Whether the token is usable at <paramref name="now"/>.</summary>
    public bool IsActive(DateTimeOffset now) => !Revoked && (ExpiresAt is null || now < ExpiresAt);

    /// <summary>Creates a shallow copy.</summary>
    public TokenRecord Clone() => (TokenRecord)MemberwiseClone();
}
