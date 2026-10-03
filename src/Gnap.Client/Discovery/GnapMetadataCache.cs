using System.Collections.Concurrent;

namespace Gnap.Client.Discovery;

/// <summary>
/// A thread-safe in-memory cache of AS discovery documents, keyed by the URI
/// they were fetched from. Register it as a singleton so that short-lived
/// <see cref="GnapClient"/> instances (typed HTTP clients) share it.
/// </summary>
public sealed class GnapMetadataCache
{
    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates an empty cache.</summary>
    public GnapMetadataCache(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Returns the cached document for the URI when present and not yet expired.</summary>
    public bool TryGet(Uri source, out AuthorizationServerMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (_entries.TryGetValue(source.AbsoluteUri, out var entry) && entry.ExpiresAt > _timeProvider.GetUtcNow())
        {
            metadata = entry.Metadata;
            return true;
        }

        metadata = null!;
        return false;
    }

    /// <summary>Stores a document for the given lifetime.</summary>
    public void Set(Uri source, AuthorizationServerMetadata metadata, TimeSpan lifetime)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(metadata);
        _entries[source.AbsoluteUri] = new Entry(metadata, _timeProvider.GetUtcNow() + lifetime);
    }

    /// <summary>Removes the cached document for the URI, forcing the next lookup to fetch it again.</summary>
    public void Invalidate(Uri source)
    {
        ArgumentNullException.ThrowIfNull(source);
        _entries.TryRemove(source.AbsoluteUri, out _);
    }

    private sealed record Entry(AuthorizationServerMetadata Metadata, DateTimeOffset ExpiresAt);
}
