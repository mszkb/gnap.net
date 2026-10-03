using System.Collections.Concurrent;
using Gnap.Core.Keys;

namespace Gnap.AspNetCore.AuthorizationServer.Stores;

/// <summary>
/// The in-memory <see cref="IGrantStore"/>: suitable for a single process and for
/// tests. Records are copied on the way in and out, so callers never share state
/// with the store and the version check is meaningful.
/// </summary>
public sealed class InMemoryGrantStore : IGrantStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, GrantRecord> _grants = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _byInteraction = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _byUserCode = new(StringComparer.Ordinal);

    /// <summary>The number of stored grants.</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _grants.Count;
            }
        }
    }

    /// <inheritdoc />
    public Task CreateAsync(GrantRecord grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        lock (_gate)
        {
            if (_grants.ContainsKey(grant.Id))
            {
                throw new InvalidOperationException("A grant with this identifier already exists.");
            }

            Index(null, grant);
            _grants[grant.Id] = grant.Clone();
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_grants.TryGetValue(grantId, out var grant) ? grant.Clone() : null);
        }
    }

    /// <inheritdoc />
    public Task<GrantRecord?> FindByInteractionIdAsync(string interactionId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_byInteraction.TryGetValue(interactionId, out var id) ? _grants[id].Clone() : null);
        }
    }

    /// <inheritdoc />
    public Task<GrantRecord?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_byUserCode.TryGetValue(userCode, out var id) ? _grants[id].Clone() : null);
        }
    }

    /// <inheritdoc />
    public Task<bool> TryUpdateAsync(GrantRecord grant, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grant);
        lock (_gate)
        {
            if (!_grants.TryGetValue(grant.Id, out var stored) || stored.Version != grant.Version)
            {
                return Task.FromResult(false);
            }

            grant.Version++;
            Index(stored, grant);
            _grants[grant.Id] = grant.Clone();
            return Task.FromResult(true);
        }
    }

    private void Index(GrantRecord? previous, GrantRecord current)
    {
        if (previous?.InteractionId is { } oldInteraction && oldInteraction != current.InteractionId)
        {
            _byInteraction.Remove(oldInteraction);
        }

        if (previous?.UserCode is { } oldCode && oldCode != current.UserCode)
        {
            _byUserCode.Remove(oldCode);
        }

        if (current.InteractionId is { } interaction)
        {
            _byInteraction[interaction] = current.Id;
        }

        if (current.UserCode is { } code)
        {
            _byUserCode[code] = current.Id;
        }
    }
}

/// <summary>The in-memory <see cref="ITokenStore"/>: suitable for a single process and for tests.</summary>
public sealed class InMemoryTokenStore : ITokenStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, TokenRecord> _tokens = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _byValueHash = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _byManageId = new(StringComparer.Ordinal);

    /// <summary>All stored tokens (copies), for diagnostics and tests.</summary>
    public IReadOnlyList<TokenRecord> Tokens
    {
        get
        {
            lock (_gate)
            {
                return [.. _tokens.Values.Select(t => t.Clone())];
            }
        }
    }

    /// <inheritdoc />
    public Task StoreAsync(TokenRecord token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        lock (_gate)
        {
            _tokens[token.Id] = token.Clone();
            _byValueHash[token.ValueHash] = token.Id;
            if (token.ManageId is { } manageId)
            {
                _byManageId[manageId] = token.Id;
            }
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<TokenRecord?> FindByValueHashAsync(string valueHash, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_byValueHash.TryGetValue(valueHash, out var id) ? _tokens[id].Clone() : null);
        }
    }

    /// <inheritdoc />
    public Task<TokenRecord?> FindByManageIdAsync(string manageId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            return Task.FromResult(_byManageId.TryGetValue(manageId, out var id) ? _tokens[id].Clone() : null);
        }
    }

    /// <inheritdoc />
    public Task<bool> RevokeAsync(string tokenId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            if (!_tokens.TryGetValue(tokenId, out var token) || token.Revoked)
            {
                return Task.FromResult(false);
            }

            token.Revoked = true;
            return Task.FromResult(true);
        }
    }

    /// <inheritdoc />
    public Task RevokeByGrantAsync(string grantId, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            foreach (var token in _tokens.Values.Where(t => t.GrantId == grantId))
            {
                token.Revoked = true;
            }
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// The in-memory <see cref="IClientKeyStore"/>. Pre-register instances and key
/// references with <see cref="AddInstance"/> and <see cref="AddKeyReference"/>.
/// </summary>
public sealed class InMemoryClientKeyStore : IClientKeyStore
{
    private readonly ConcurrentDictionary<string, ClientRegistration> _instances = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, GnapKey> _keys = new(StringComparer.Ordinal);

    /// <summary>Registers a client instance.</summary>
    public InMemoryClientKeyStore AddInstance(ClientRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        _instances[registration.InstanceId] = registration;
        return this;
    }

    /// <summary>Registers a key reference.</summary>
    public InMemoryClientKeyStore AddKeyReference(string keyReference, GnapKey key)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyReference);
        ArgumentNullException.ThrowIfNull(key);
        _keys[keyReference] = key;
        return this;
    }

    /// <inheritdoc />
    public Task<ClientRegistration?> FindInstanceAsync(string instanceId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_instances.GetValueOrDefault(instanceId));

    /// <inheritdoc />
    public Task<GnapKey?> FindKeyAsync(string keyReference, CancellationToken cancellationToken = default) =>
        Task.FromResult(_keys.GetValueOrDefault(keyReference));

    /// <inheritdoc />
    public Task RegisterInstanceAsync(ClientRegistration registration, CancellationToken cancellationToken = default)
    {
        AddInstance(registration);
        return Task.CompletedTask;
    }
}

/// <summary>The in-memory <see cref="IResourceServerStore"/>. Register resource servers with <see cref="Add"/>.</summary>
public sealed class InMemoryResourceServerStore : IResourceServerStore
{
    private readonly ConcurrentDictionary<string, ResourceServerRegistration> _servers = new(StringComparer.Ordinal);

    /// <summary>Registers a resource server.</summary>
    public InMemoryResourceServerStore Add(ResourceServerRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);
        _servers[registration.Id] = registration;
        return this;
    }

    /// <inheritdoc />
    public Task<ResourceServerRegistration?> FindAsync(string resourceServerId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_servers.GetValueOrDefault(resourceServerId));
}

/// <summary>An in-memory <see cref="IResourceSetStore"/>.</summary>
public sealed class InMemoryResourceSetStore : IResourceSetStore
{
    private readonly ConcurrentDictionary<string, ResourceSetRegistration> _sets = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public Task StoreAsync(ResourceSetRegistration registration, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(registration);
        _sets[registration.Reference] = registration;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ResourceSetRegistration?> FindAsync(string reference, CancellationToken cancellationToken = default) =>
        Task.FromResult(_sets.GetValueOrDefault(reference));
}
