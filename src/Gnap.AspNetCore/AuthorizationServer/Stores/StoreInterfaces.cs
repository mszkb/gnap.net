using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.AspNetCore.AuthorizationServer.Stores;

/// <summary>
/// Persists grants. Implementations must make <see cref="TryUpdateAsync"/> an
/// atomic compare-and-swap on <see cref="GrantRecord.Version"/>: it is what makes
/// interaction references, user codes and continuation tokens single-use even
/// under concurrent requests.
/// </summary>
public interface IGrantStore
{
    /// <summary>Stores a new grant.</summary>
    Task CreateAsync(GrantRecord grant, CancellationToken cancellationToken = default);

    /// <summary>Finds a grant by its identifier.</summary>
    Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken = default);

    /// <summary>Finds a grant by the identifier in its interaction redirect URI.</summary>
    Task<GrantRecord?> FindByInteractionIdAsync(string interactionId, CancellationToken cancellationToken = default);

    /// <summary>Finds a grant by its normalized user code.</summary>
    Task<GrantRecord?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces the stored grant if its stored version still equals
    /// <paramref name="grant"/>.<see cref="GrantRecord.Version"/>; on success the
    /// version is incremented (on the stored copy and on <paramref name="grant"/>).
    /// </summary>
    /// <returns><see langword="false"/> when the grant was changed concurrently or does not exist.</returns>
    Task<bool> TryUpdateAsync(GrantRecord grant, CancellationToken cancellationToken = default);
}

/// <summary>Persists issued access tokens.</summary>
public interface ITokenStore
{
    /// <summary>Stores a newly issued token.</summary>
    Task StoreAsync(TokenRecord token, CancellationToken cancellationToken = default);

    /// <summary>Finds a token by the SHA-256 hash of its value.</summary>
    Task<TokenRecord?> FindByValueHashAsync(string valueHash, CancellationToken cancellationToken = default);

    /// <summary>Finds a token by the identifier in its management URI.</summary>
    Task<TokenRecord?> FindByManageIdAsync(string manageId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a token atomically. Returns <see langword="true"/> only for the call
    /// that changed it from active to revoked, which makes rotation single-use.
    /// </summary>
    Task<bool> RevokeAsync(string tokenId, CancellationToken cancellationToken = default);

    /// <summary>Revokes every token issued for a grant (when the grant is revoked).</summary>
    Task RevokeByGrantAsync(string grantId, CancellationToken cancellationToken = default);
}

/// <summary>A client instance known to the AS (RFC 9635 Section 2.3.1).</summary>
public sealed class ClientRegistration
{
    /// <summary>The instance identifier the client sends by reference.</summary>
    public required string InstanceId { get; init; }

    /// <summary>The client instance's key (by value, with its proof method).</summary>
    public required GnapKey Key { get; init; }

    /// <summary>The client software identifier.</summary>
    public string? ClassId { get; init; }

    /// <summary>Display information for the RO.</summary>
    public ClientDisplay? Display { get; init; }
}

/// <summary>
/// Resolves client instances and keys passed by reference (RFC 9635 Sections
/// 2.3.1 and 7.1.1), and records instance identifiers issued by the AS.
/// </summary>
public interface IClientKeyStore
{
    /// <summary>Finds a client instance by its instance identifier.</summary>
    Task<ClientRegistration?> FindInstanceAsync(string instanceId, CancellationToken cancellationToken = default);

    /// <summary>Resolves a key reference to key material (by value, with its proof method).</summary>
    Task<GnapKey?> FindKeyAsync(string keyReference, CancellationToken cancellationToken = default);

    /// <summary>Registers a client instance, e.g. one the AS just assigned an <c>instance_id</c>.</summary>
    Task RegisterInstanceAsync(ClientRegistration registration, CancellationToken cancellationToken = default);
}

/// <summary>A resource server allowed to call the introspection endpoint (RFC 9767).</summary>
public sealed class ResourceServerRegistration
{
    /// <summary>The identifier the RS sends as <c>resource_server</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The key the RS signs its introspection requests with (by value, with its proof method).</summary>
    public required GnapKey Key { get; init; }
}

/// <summary>Resolves resource servers for the RS-facing endpoints (RFC 9767).</summary>
public interface IResourceServerStore
{
    /// <summary>Finds a resource server by its identifier.</summary>
    Task<ResourceServerRegistration?> FindAsync(string resourceServerId, CancellationToken cancellationToken = default);
}
