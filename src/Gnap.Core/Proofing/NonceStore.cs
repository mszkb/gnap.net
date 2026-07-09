using System.Collections.Concurrent;

namespace Gnap.Core.Proofing;

/// <summary>
/// Tracks signature nonces for replay protection. A nonce may be accepted at
/// most once within its validity window.
/// </summary>
public interface INonceStore
{
    /// <summary>
    /// Registers a nonce. Returns <see langword="false"/> if the nonce was already
    /// seen (a replay); <see langword="true"/> if it was accepted and recorded
    /// until <paramref name="expires"/>.
    /// </summary>
    ValueTask<bool> TryRegisterAsync(string nonce, DateTimeOffset expires, CancellationToken cancellationToken = default);
}

/// <summary>
/// An in-memory <see cref="INonceStore"/> for single-process deployments and
/// tests. Expired entries are pruned opportunistically on registration.
/// </summary>
public sealed class InMemoryNonceStore : INonceStore
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the store; the clock is overridable for tests.</summary>
    public InMemoryNonceStore(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public ValueTask<bool> TryRegisterAsync(string nonce, DateTimeOffset expires, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(nonce);
        var now = _timeProvider.GetUtcNow();
        Prune(now);

        // A nonce that is present but expired may be accepted again: re-registering
        // must replace the stale entry atomically, not fail as a replay.
        while (true)
        {
            if (_seen.TryAdd(nonce, expires))
            {
                return ValueTask.FromResult(true);
            }

            if (!_seen.TryGetValue(nonce, out var existing))
            {
                continue;
            }

            if (existing > now)
            {
                return ValueTask.FromResult(false);
            }

            if (_seen.TryUpdate(nonce, expires, existing))
            {
                return ValueTask.FromResult(true);
            }
        }
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var (nonce, expiry) in _seen)
        {
            if (expiry <= now)
            {
                _seen.TryRemove(KeyValuePair.Create(nonce, expiry));
            }
        }
    }
}
