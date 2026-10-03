using System.Collections.Concurrent;

namespace Gnap.HttpMessageSignatures;

/// <summary>
/// Remembers signature nonces for replay protection (RFC 9421 Section 7.2.2).
/// A nonce may be accepted at most once per key within its validity window.
/// </summary>
/// <remarks>
/// Nonces are scoped by <c>keyid</c>, so different clients choosing the same
/// nonce value do not collide. Implementations shared between several server
/// instances (e.g. backed by a distributed cache) must make
/// <see cref="TryAddAsync"/> atomic.
/// </remarks>
public interface INonceStore
{
    /// <summary>
    /// Records <paramref name="nonce"/> for <paramref name="keyId"/>. Returns
    /// <see langword="false"/> if that pair was already recorded and has not yet
    /// expired (a replay); <see langword="true"/> if it was accepted and is now
    /// remembered until <paramref name="expiresAt"/>.
    /// </summary>
    /// <param name="keyId">The signature's <c>keyid</c>; the empty string when the signature has none.</param>
    /// <param name="nonce">The signature's <c>nonce</c> parameter.</param>
    /// <param name="expiresAt">When the entry may be forgotten: the end of the signature's acceptance window.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    ValueTask<bool> TryAddAsync(string keyId, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default);
}

/// <summary>
/// An in-memory <see cref="INonceStore"/> for single-process deployments and
/// tests. Expired entries are pruned opportunistically on every add.
/// </summary>
public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<(string KeyId, string Nonce), DateTimeOffset> _seen = new();
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the store; the clock is overridable for tests.</summary>
    public InMemoryNonceStore(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>The number of entries currently held, including expired ones not yet pruned.</summary>
    public int Count => _seen.Count;

    /// <summary>Whether an unexpired entry for the key/nonce pair is currently held.</summary>
    public bool Contains(string keyId, string nonce) =>
        _seen.TryGetValue((keyId, nonce), out var expiry) && expiry > _timeProvider.GetUtcNow();

    /// <inheritdoc />
    public ValueTask<bool> TryAddAsync(string keyId, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyId);
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        var now = _timeProvider.GetUtcNow();
        Prune(now);

        var key = (keyId, nonce);

        // A nonce that is present but expired may be accepted again: re-adding
        // must replace the stale entry atomically, not fail as a replay.
        while (true)
        {
            if (_seen.TryAdd(key, expiresAt))
            {
                return ValueTask.FromResult(true);
            }

            if (!_seen.TryGetValue(key, out var existing))
            {
                continue;
            }

            if (existing > now)
            {
                return ValueTask.FromResult(false);
            }

            if (_seen.TryUpdate(key, expiresAt, existing))
            {
                return ValueTask.FromResult(true);
            }
        }
    }

    /// <summary>Removes all entries whose window has ended.</summary>
    public void Prune() => Prune(_timeProvider.GetUtcNow());

    private void Prune(DateTimeOffset now)
    {
        foreach (var (key, expiry) in _seen)
        {
            if (expiry <= now)
            {
                _seen.TryRemove(KeyValuePair.Create(key, expiry));
            }
        }
    }
}
