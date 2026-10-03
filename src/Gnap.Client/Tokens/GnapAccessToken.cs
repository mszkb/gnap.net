using Gnap.Core;
using Gnap.Core.Models;

namespace Gnap.Client.Tokens;

/// <summary>
/// An access token issued to the client instance, together with the client-side
/// bookkeeping needed to use and manage it: when it was received, when it
/// expires and which client key it is bound to.
/// </summary>
public sealed class GnapAccessToken
{
    /// <summary>Wraps an issued token.</summary>
    /// <param name="token">The token as returned by the AS.</param>
    /// <param name="boundKey">
    /// The client key that proves possession for this token; <see langword="null"/>
    /// for bearer tokens and for tokens bound to a key the client does not hold.
    /// </param>
    /// <param name="managementKey">The key that signs token management calls (the client instance key).</param>
    /// <param name="issuedAt">When the client received the token.</param>
    public GnapAccessToken(AccessTokenResponse token, GnapClientKey? boundKey, GnapClientKey managementKey, DateTimeOffset issuedAt)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(managementKey);
        if (string.IsNullOrEmpty(token.Value))
        {
            throw new GnapClientException("The access token has no value.");
        }

        Token = token;
        BoundKey = boundKey;
        ManagementKey = managementKey;
        IssuedAt = issuedAt;
        ExpiresAt = token.ExpiresIn is { } seconds ? issuedAt.AddSeconds(seconds) : null;
    }

    /// <summary>The token as returned by the AS.</summary>
    public AccessTokenResponse Token { get; }

    /// <summary>The token value.</summary>
    public string Value => Token.Value!;

    /// <summary>The token label, when the client requested several tokens.</summary>
    public string? Label => Token.Label;

    /// <summary>The rights of access granted with this token.</summary>
    public IList<AccessRight>? Access => Token.Access;

    /// <summary>Whether the token is a bearer token (no key proof when presenting it).</summary>
    public bool IsBearer => Token.IsBearer;

    /// <summary>The client key presentations of this token are signed with.</summary>
    public GnapClientKey? BoundKey { get; }

    /// <summary>The key that signs management calls (rotation, revocation) for this token.</summary>
    public GnapClientKey ManagementKey { get; }

    /// <summary>When the client received the token.</summary>
    public DateTimeOffset IssuedAt { get; }

    /// <summary>When the token expires, computed from <c>expires_in</c>; <see langword="null"/> when unknown.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Whether the token offers token management (rotation and revocation).</summary>
    public bool CanBeManaged => Token.Manage is { Uri: not null } manage && manage.GetManagementTokenValue(Token.Value) is not null;

    /// <summary>Whether the token has expired at <paramref name="now"/>, treating the last <paramref name="skew"/> as expired.</summary>
    public bool IsExpired(DateTimeOffset now, TimeSpan skew = default) => ExpiresAt is { } expiresAt && now + skew >= expiresAt;

    /// <summary>
    /// Presents the token on an outgoing RS request (RFC 9635 Section 7.2): sets
    /// <c>Authorization: GNAP &lt;value&gt;</c> and, unless the token is a bearer
    /// token, signs the request with the bound key covering that header.
    /// </summary>
    /// <exception cref="GnapClientException">The token is bound to a key the client does not hold.</exception>
    public async Task ApplyAsync(HttpRequestMessage request, TimeProvider? timeProvider = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IsBearer && BoundKey is null)
        {
            throw new GnapClientException("The access token is bound to a key the client instance does not hold.");
        }

        GnapAuthorization.Apply(request, Value);
        if (!IsBearer)
        {
            await BoundKey!.CreateProofer(timeProvider).AddProofAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Creates the bookkeeping for a token issued by the AS to a client using <paramref name="clientKey"/>.</summary>
    internal static GnapAccessToken FromResponse(AccessTokenResponse token, GnapClientKey clientKey, DateTimeOffset now) =>
        new(token, token.IsBoundToClientKey ? clientKey : null, clientKey, now);

    /// <summary>Applies the result of a rotation; a missing <c>manage</c> keeps the previous management access.</summary>
    internal GnapAccessToken WithRotated(AccessTokenResponse rotated, GnapClientKey? boundKey, GnapClientKey managementKey, DateTimeOffset now)
    {
        rotated.Manage ??= Token.Manage;
        rotated.Label ??= Token.Label;
        rotated.Access ??= Token.Access;
        return new GnapAccessToken(rotated, boundKey, managementKey, now);
    }
}
