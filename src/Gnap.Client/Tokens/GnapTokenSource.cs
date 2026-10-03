namespace Gnap.Client.Tokens;

/// <summary>
/// Holds the current value of an access token and keeps it usable: when the
/// token is about to expire (or an RS rejected it) it is rotated through the
/// token management API (RFC 9635 Section 6.1), which is GNAP's refresh
/// mechanism. Thread-safe; concurrent callers share one rotation.
/// </summary>
public sealed class GnapTokenSource
{
    private readonly GnapClient _client;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private GnapAccessToken _current;

    /// <summary>Creates a token source for a token issued through <paramref name="client"/>.</summary>
    public GnapTokenSource(GnapClient client, GnapAccessToken token)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(token);
        _client = client;
        _current = token;
    }

    /// <summary>The current token, without any expiry check.</summary>
    public GnapAccessToken Current => Volatile.Read(ref _current);

    /// <summary>The clock used for expiry checks.</summary>
    public TimeProvider TimeProvider => _client.Options.TimeProvider;

    /// <summary>
    /// Returns a token that is not (about to be) expired, rotating it first when
    /// necessary. Tokens without <c>expires_in</c> are returned as they are.
    /// </summary>
    /// <exception cref="GnapClientException">The token expired and cannot be rotated.</exception>
    public async Task<GnapAccessToken> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        var token = Current;
        if (!token.IsExpired(TimeProvider.GetUtcNow(), _client.Options.TokenRefreshSkew))
        {
            return token;
        }

        return await RefreshAsync(token, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Rotates the token unless another caller already replaced <paramref name="staleToken"/>
    /// (e.g. after an RS answered 401 for it).
    /// </summary>
    /// <exception cref="GnapClientException">The token cannot be rotated.</exception>
    public async Task<GnapAccessToken> RefreshAsync(GnapAccessToken staleToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(staleToken);
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!ReferenceEquals(_current, staleToken))
            {
                return _current;
            }

            if (!staleToken.CanBeManaged)
            {
                throw new GnapClientException("The access token expired and offers no token management for rotation; request a new grant.");
            }

            var rotated = await _client.RotateTokenAsync(staleToken, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _current, rotated);
            return rotated;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Rotates the key bound to the token (RFC 9635 Section 6.1.2) and keeps the result.</summary>
    /// <exception cref="GnapClientException">The token cannot be managed or the AS refused the rotation.</exception>
    public async Task<GnapAccessToken> RotateKeyAsync(GnapClientKey newKey, CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var rotated = await _client.RotateTokenKeyAsync(_current, newKey, cancellationToken).ConfigureAwait(false);
            Volatile.Write(ref _current, rotated);
            return rotated;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary>Revokes the token at the AS (RFC 9635 Section 6.2).</summary>
    /// <exception cref="GnapClientException">The token cannot be managed or the AS refused the revocation.</exception>
    public async Task RevokeAsync(CancellationToken cancellationToken = default)
    {
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _client.RevokeTokenAsync(_current, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lock.Release();
        }
    }
}
