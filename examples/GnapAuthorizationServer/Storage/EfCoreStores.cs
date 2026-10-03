using System.Text.Json;
using System.Text.Json.Serialization;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Keys;
using Microsoft.EntityFrameworkCore;

namespace GnapAuthorizationServer.Storage;

// An example of persistent storage for the AS with EF Core. Each record is stored
// as a JSON document plus the columns the stores query by; the grant's Version
// column implements the optimistic concurrency that IGrantStore requires.

/// <summary>The EF Core model of the AS state.</summary>
public sealed class GnapDbContext(DbContextOptions<GnapDbContext> options) : DbContext(options)
{
    /// <summary>The grants.</summary>
    public DbSet<GrantEntity> Grants => Set<GrantEntity>();

    /// <summary>The issued access tokens.</summary>
    public DbSet<TokenEntity> Tokens => Set<TokenEntity>();

    /// <summary>Registered client instances.</summary>
    public DbSet<ClientEntity> Clients => Set<ClientEntity>();

    /// <summary>Registered key references.</summary>
    public DbSet<KeyReferenceEntity> KeyReferences => Set<KeyReferenceEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<GrantEntity>().HasIndex(g => g.InteractionId);
        modelBuilder.Entity<GrantEntity>().HasIndex(g => g.UserCode);
        modelBuilder.Entity<TokenEntity>().HasIndex(t => t.ValueHash).IsUnique();
        modelBuilder.Entity<TokenEntity>().HasIndex(t => t.ManageId);
        modelBuilder.Entity<TokenEntity>().HasIndex(t => t.GrantId);
    }
}

/// <summary>A stored grant.</summary>
public sealed class GrantEntity
{
    /// <summary>The grant identifier.</summary>
    public required string Id { get; set; }

    /// <summary>The interaction identifier, for lookup.</summary>
    public string? InteractionId { get; set; }

    /// <summary>The normalized user code, for lookup.</summary>
    public string? UserCode { get; set; }

    /// <summary>The optimistic concurrency version.</summary>
    public long Version { get; set; }

    /// <summary>The serialized <see cref="GrantRecord"/>.</summary>
    public required string Json { get; set; }
}

/// <summary>A stored access token.</summary>
public sealed class TokenEntity
{
    /// <summary>The token identifier.</summary>
    public required string Id { get; set; }

    /// <summary>The SHA-256 hash of the token value.</summary>
    public required string ValueHash { get; set; }

    /// <summary>The management identifier.</summary>
    public string? ManageId { get; set; }

    /// <summary>The grant identifier.</summary>
    public required string GrantId { get; set; }

    /// <summary>Whether the token is revoked (authoritative over the JSON copy).</summary>
    public bool Revoked { get; set; }

    /// <summary>The serialized <see cref="TokenRecord"/>.</summary>
    public required string Json { get; set; }
}

/// <summary>A registered client instance.</summary>
public sealed class ClientEntity
{
    /// <summary>The instance identifier.</summary>
    [System.ComponentModel.DataAnnotations.Key]
    public required string InstanceId { get; set; }

    /// <summary>The serialized <see cref="ClientRegistration"/>.</summary>
    public required string Json { get; set; }
}

/// <summary>A registered key reference.</summary>
public sealed class KeyReferenceEntity
{
    /// <summary>The key reference.</summary>
    [System.ComponentModel.DataAnnotations.Key]
    public required string Reference { get; set; }

    /// <summary>The serialized <see cref="GnapKey"/>.</summary>
    public required string Json { get; set; }
}

internal static class StoreJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}

/// <summary>An EF Core <see cref="IGrantStore"/>.</summary>
public sealed class EfGrantStore(GnapDbContext db) : IGrantStore
{
    /// <inheritdoc />
    public async Task CreateAsync(GrantRecord grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        db.Grants.Add(new GrantEntity
        {
            Id = grant.Id,
            InteractionId = grant.InteractionId,
            UserCode = grant.UserCode,
            Version = grant.Version,
            Json = JsonSerializer.Serialize(grant, StoreJson.Options),
        });
        await db.SaveChangesAsync(cancellationToken);
        db.ChangeTracker.Clear();
    }

    /// <inheritdoc />
    public Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken = default) =>
        FindAsync(db.Grants.Where(g => g.Id == grantId), cancellationToken);

    /// <inheritdoc />
    public Task<GrantRecord?> FindByInteractionIdAsync(string interactionId, CancellationToken cancellationToken = default) =>
        FindAsync(db.Grants.Where(g => g.InteractionId == interactionId), cancellationToken);

    /// <inheritdoc />
    public Task<GrantRecord?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default) =>
        FindAsync(db.Grants.Where(g => g.UserCode == userCode), cancellationToken);

    /// <inheritdoc />
    public async Task<bool> TryUpdateAsync(GrantRecord grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        var expected = grant.Version;
        var json = JsonSerializer.Serialize(grant, StoreJson.Options);
        var updated = await db.Grants
            .Where(g => g.Id == grant.Id && g.Version == expected)
            .ExecuteUpdateAsync(
                s => s.SetProperty(g => g.Version, expected + 1)
                    .SetProperty(g => g.Json, json)
                    .SetProperty(g => g.InteractionId, grant.InteractionId)
                    .SetProperty(g => g.UserCode, grant.UserCode),
                cancellationToken);
        if (updated != 1)
        {
            return false;
        }

        grant.Version = expected + 1;
        return true;
    }

    private static async Task<GrantRecord?> FindAsync(IQueryable<GrantEntity> query, CancellationToken cancellationToken)
    {
        var entity = await query.AsNoTracking().FirstOrDefaultAsync(cancellationToken);
        if (entity is null)
        {
            return null;
        }

        var grant = JsonSerializer.Deserialize<GrantRecord>(entity.Json, StoreJson.Options)!;
        grant.Version = entity.Version;
        return grant;
    }
}

/// <summary>An EF Core <see cref="ITokenStore"/>.</summary>
public sealed class EfTokenStore(GnapDbContext db) : ITokenStore
{
    /// <inheritdoc />
    public async Task StoreAsync(TokenRecord token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        db.Tokens.Add(new TokenEntity
        {
            Id = token.Id,
            ValueHash = token.ValueHash,
            ManageId = token.ManageId,
            GrantId = token.GrantId,
            Revoked = token.Revoked,
            Json = JsonSerializer.Serialize(token, StoreJson.Options),
        });
        await db.SaveChangesAsync(cancellationToken);
        db.ChangeTracker.Clear();
    }

    /// <inheritdoc />
    public Task<TokenRecord?> FindByValueHashAsync(string valueHash, CancellationToken cancellationToken = default) =>
        FindAsync(db.Tokens.Where(t => t.ValueHash == valueHash), cancellationToken);

    /// <inheritdoc />
    public Task<TokenRecord?> FindByManageIdAsync(string manageId, CancellationToken cancellationToken = default) =>
        FindAsync(db.Tokens.Where(t => t.ManageId == manageId), cancellationToken);

    /// <inheritdoc />
    public async Task<bool> RevokeAsync(string tokenId, CancellationToken cancellationToken = default) =>
        await db.Tokens
            .Where(t => t.Id == tokenId && !t.Revoked)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Revoked, true), cancellationToken) == 1;

    /// <inheritdoc />
    public Task RevokeByGrantAsync(string grantId, CancellationToken cancellationToken = default) =>
        db.Tokens
            .Where(t => t.GrantId == grantId)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Revoked, true), cancellationToken);

    private static async Task<TokenRecord?> FindAsync(IQueryable<TokenEntity> query, CancellationToken cancellationToken)
    {
        var entity = await query.AsNoTracking().FirstOrDefaultAsync(cancellationToken);
        if (entity is null)
        {
            return null;
        }

        var token = JsonSerializer.Deserialize<TokenRecord>(entity.Json, StoreJson.Options)!;
        token.Revoked = entity.Revoked;
        return token;
    }
}

/// <summary>An EF Core <see cref="IClientKeyStore"/>.</summary>
public sealed class EfClientKeyStore(GnapDbContext db) : IClientKeyStore
{
    /// <inheritdoc />
    public async Task<ClientRegistration?> FindInstanceAsync(string instanceId, CancellationToken cancellationToken = default)
    {
        var entity = await db.Clients.AsNoTracking().FirstOrDefaultAsync(c => c.InstanceId == instanceId, cancellationToken);
        return entity is null ? null : JsonSerializer.Deserialize<ClientRegistration>(entity.Json, StoreJson.Options);
    }

    /// <inheritdoc />
    public async Task<GnapKey?> FindKeyAsync(string keyReference, CancellationToken cancellationToken = default)
    {
        var entity = await db.KeyReferences.AsNoTracking().FirstOrDefaultAsync(k => k.Reference == keyReference, cancellationToken);
        return entity is null ? null : JsonSerializer.Deserialize<GnapKey>(entity.Json, StoreJson.Options);
    }

    /// <inheritdoc />
    public async Task RegisterInstanceAsync(ClientRegistration registration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        db.Clients.Add(new ClientEntity { InstanceId = registration.InstanceId, Json = JsonSerializer.Serialize(registration, StoreJson.Options) });
        await db.SaveChangesAsync(cancellationToken);
        db.ChangeTracker.Clear();
    }
}
