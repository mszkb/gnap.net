using System.Buffers.Text;
using System.Text;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Endpoints;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Gnap.Core;
using Gnap.Core.Keys;
using Gnap.HttpMessageSignatures;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>
/// Resolves a presented access token value to what is known about it. Implementations
/// only establish that the AS issued the token and that it is active; the RS middleware
/// then enforces expiry, the key proof of key-bound tokens and the bearer policy.
/// </summary>
public interface IGnapTokenValidator
{
    /// <summary>Describes an active token; <see langword="null"/> for unknown, inactive, revoked or forged tokens.</summary>
    ValueTask<GnapTokenInfo?> ValidateAsync(string accessToken, CancellationToken cancellationToken = default);
}

/// <summary>
/// Validates tokens by introspection at the AS (RFC 9767 Section 3.3) through
/// <see cref="GnapAsRsClient"/>, caching results in <see cref="GnapIntrospectionCache"/>
/// (active results at most <see cref="GnapResourceServerOptions.IntrospectionCacheDuration"/>
/// and never beyond the token's expiry, inactive ones for
/// <see cref="GnapResourceServerOptions.NegativeCacheDuration"/>). Works with every
/// token format, including opaque tokens. Failed AS calls are not cached.
/// </summary>
public sealed class IntrospectionTokenValidator(
    GnapAsRsClient client,
    GnapIntrospectionCache cache,
    IOptionsMonitor<GnapResourceServerOptions> options,
    ILogger<IntrospectionTokenValidator> logger) : IGnapTokenValidator
{
    /// <inheritdoc />
    public async ValueTask<GnapTokenInfo?> ValidateAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        if (cache.TryGet(accessToken, out var cached))
        {
            return cached;
        }

        GnapTokenInfo? info;
        try
        {
            info = await client.IntrospectAsync(accessToken, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (GnapException e)
        {
            logger.LogWarning("Token introspection failed: {Reason}", e.Message);
            return null;
        }

        var settings = options.Get(GnapResourceServerDefaults.AuthenticationScheme);
        cache.Set(accessToken, info, info is null ? settings.NegativeCacheDuration : settings.IntrospectionCacheDuration);
        return info;
    }
}

/// <summary>
/// Validates tokens against the <see cref="ITokenStore"/> of an AS hosted in the same
/// application (<c>AddGnapAuthorizationServer</c>): local verification for every token
/// format, with revocation and expiry visible immediately.
/// </summary>
public sealed class TokenStoreValidator(ITokenStore tokenStore, IOptionsMonitor<GnapResourceServerOptions> options) : IGnapTokenValidator
{
    /// <inheritdoc />
    public async ValueTask<GnapTokenInfo?> ValidateAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        var token = await tokenStore.FindByValueHashAsync(Protocol.Hash(accessToken), cancellationToken).ConfigureAwait(false);
        var now = (options.Get(GnapResourceServerDefaults.AuthenticationScheme).TimeProvider ?? TimeProvider.System).GetUtcNow();
        if (token is null || !token.IsActive(now))
        {
            return null;
        }

        return new GnapTokenInfo
        {
            Access = token.Access,
            Key = token.BoundKey,
            Flags = token.IsBearer ? [Core.Models.AccessTokenFlags.Bearer] : [],
            IssuedAt = token.IssuedAt,
            ExpiresAt = token.ExpiresAt,
            Issuer = token.Issuer,
            Subject = token.ResourceOwner,
            InstanceId = token.InstanceId,
            TokenId = token.Id,
        };
    }
}

/// <summary>
/// Validates self-contained JWT access tokens issued by <see cref="JwtTokenFormat"/>
/// locally, without contacting the AS: the JWS signature against the AS's public
/// key(s), <c>typ</c>, the optional expected issuer, and the consistency of the bound
/// <c>key</c> with <c>cnf.jkt</c>. Expiry is checked by the middleware. Revocation at the
/// AS is <b>not</b> visible to local validation; keep token lifetimes short, or use
/// introspection where immediate revocation matters.
/// </summary>
public sealed class JwtTokenValidator : IGnapTokenValidator
{
    private readonly IReadOnlyList<JsonWebKey> _keys;
    private readonly string? _issuer;

    /// <summary>Creates the validator.</summary>
    /// <param name="signingKeys">The AS's public JWT signing keys (e.g. <see cref="JwtTokenFormat.PublicKey"/>).</param>
    /// <param name="issuer">The expected <c>iss</c> (the AS grant endpoint URI); <see langword="null"/> skips the check.</param>
    public JwtTokenValidator(IEnumerable<JsonWebKey> signingKeys, string? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(signingKeys);
        _keys = signingKeys.Select(k => k.ToPublicKey()).ToArray();
        if (_keys.Count == 0)
        {
            throw new ArgumentException("At least one signing key is required.", nameof(signingKeys));
        }

        _issuer = issuer;
    }

    /// <inheritdoc />
    public ValueTask<GnapTokenInfo?> ValidateAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        return ValueTask.FromResult(Validate(accessToken));
    }

    private GnapTokenInfo? Validate(string accessToken)
    {
        var parts = accessToken.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        try
        {
            using var header = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[0]));
            var h = header.RootElement;
            if (h.ValueKind != JsonValueKind.Object
                || !h.TryGetProperty("alg", out var alg) || alg.ValueKind != JsonValueKind.String
                || !h.TryGetProperty("typ", out var typ) || typ.GetString() != JwtTokenFormat.TokenType)
            {
                return null;
            }

            var kid = h.TryGetProperty("kid", out var kidElement) && kidElement.ValueKind == JsonValueKind.String ? kidElement.GetString() : null;
            var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
            var signature = Base64Url.DecodeFromChars(parts[2]);
            if (!_keys.Where(k => kid is null || k.Kid is null || k.Kid == kid).Any(k => Verify(k, alg.GetString()!, signingInput, signature)))
            {
                return null;
            }

            using var payload = JsonDocument.Parse(Base64Url.DecodeFromChars(parts[1]));
            var claims = payload.RootElement;
            var info = GnapTokenInfo.Parse(claims, requireActive: false);
            if (info is null || (_issuer is not null && info.Issuer != _issuer))
            {
                return null;
            }

            var thumbprint = claims.TryGetProperty("cnf", out var cnf) && cnf.ValueKind == JsonValueKind.Object
                && cnf.TryGetProperty("jkt", out var jkt) && jkt.ValueKind == JsonValueKind.String
                    ? jkt.GetString()
                    : null;
            if (info.Key?.Jwk is { } jwk && thumbprint != jwk.ComputeThumbprint())
            {
                return null;
            }

            return info;
        }
        catch (Exception e) when (e is FormatException or JsonException or GnapException)
        {
            return null;
        }
    }

    private static bool Verify(JsonWebKey key, string jwsAlgorithm, byte[] signingInput, byte[] signature)
    {
        SignatureAlgorithm algorithm;
        try
        {
            algorithm = key.ToSignatureAlgorithm();
            if (JwtTokenFormat.ToJwsAlgorithm(algorithm.Name) != jwsAlgorithm)
            {
                return false;
            }
        }
        catch (GnapException)
        {
            return false;
        }

        return algorithm.Verify(signingInput, signature);
    }
}
