using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>
/// Caches introspection results by the SHA-256 hash of the token value (token values
/// themselves are never kept). Active results live at most until the token expires,
/// inactive results for a short time; <see cref="Invalidate"/> drops a token at once,
/// e.g. after learning of its revocation.
/// </summary>
public sealed class GnapIntrospectionCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly int _capacity;

    /// <summary>Creates a cache holding at most <paramref name="capacity"/> results.</summary>
    public GnapIntrospectionCache(TimeProvider? timeProvider = null, int capacity = 10_000)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _capacity = capacity;
    }

    /// <summary>The number of cached results (including expired ones not yet pruned).</summary>
    public int Count => _entries.Count;

    /// <summary>Drops the cached result for a token value.</summary>
    public void Invalidate(string tokenValue)
    {
        ArgumentNullException.ThrowIfNull(tokenValue);
        _entries.TryRemove(Hash(tokenValue), out _);
    }

    /// <summary>Drops all cached results.</summary>
    public void Clear() => _entries.Clear();

    /// <summary>Looks up a token; <paramref name="info"/> is <see langword="null"/> for a cached inactive result.</summary>
    internal bool TryGet(string tokenValue, out GnapTokenInfo? info)
    {
        var key = Hash(tokenValue);
        if (_entries.TryGetValue(key, out var entry))
        {
            if (_timeProvider.GetUtcNow() < entry.ExpiresAt)
            {
                info = entry.Info;
                return true;
            }

            _entries.TryRemove(new KeyValuePair<string, Entry>(key, entry));
        }

        info = null;
        return false;
    }

    /// <summary>
    /// Caches a result for <paramref name="duration"/>, but an active result never
    /// beyond the token's expiry.
    /// </summary>
    internal void Set(string tokenValue, GnapTokenInfo? info, TimeSpan duration)
    {
        var now = _timeProvider.GetUtcNow();
        var expiresAt = now + duration;
        if (info?.ExpiresAt is { } tokenExpiry && tokenExpiry < expiresAt)
        {
            expiresAt = tokenExpiry;
        }

        if (expiresAt <= now)
        {
            return;
        }

        if (_entries.Count >= _capacity)
        {
            Prune(now);
            if (_entries.Count >= _capacity)
            {
                _entries.Clear();
            }
        }

        _entries[Hash(tokenValue)] = new Entry(info, expiresAt);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var entry in _entries)
        {
            if (entry.Value.ExpiresAt <= now)
            {
                _entries.TryRemove(entry);
            }
        }
    }

    private static string Hash(string tokenValue) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(tokenValue)));

    private sealed record Entry(GnapTokenInfo? Info, DateTimeOffset ExpiresAt);
}
