using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.HttpMessageSignatures;

namespace Gnap.AspNetCore.AuthorizationServer.Tokens;

/// <summary>Everything known about an access token at the time its value is created.</summary>
public sealed class AccessTokenDescriptor
{
    /// <summary>The token identifier (use as JWT <c>jti</c>).</summary>
    public required string TokenId { get; init; }

    /// <summary>The grant the token is issued for.</summary>
    public required string GrantId { get; init; }

    /// <summary>The issuer: the grant endpoint URI.</summary>
    public required string Issuer { get; init; }

    /// <summary>The rights of access.</summary>
    public required IList<AccessRight> Access { get; init; }

    /// <summary>The key the token is bound to; <see langword="null"/> for a bearer token.</summary>
    public GnapKey? BoundKey { get; init; }

    /// <summary>When the token is issued.</summary>
    public DateTimeOffset IssuedAt { get; init; }

    /// <summary>When the token expires, if it does.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>The client instance identifier, if known.</summary>
    public string? InstanceId { get; init; }

    /// <summary>The approving resource owner, if known.</summary>
    public string? ResourceOwner { get; init; }
}

/// <summary>
/// Creates access token values. Every token is also recorded in the
/// <see cref="Stores.ITokenStore"/> (by the hash of its value), so revocation and
/// introspection work for every format; self-contained formats such as
/// <see cref="JwtTokenFormat"/> additionally allow local verification at the RS.
/// </summary>
public interface ITokenFormat
{
    /// <summary>Creates the token value. It must use the <c>token68</c> character set.</summary>
    ValueTask<string> CreateTokenAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default);
}

/// <summary>The default format: 256 random bits, base64url-encoded — a pure reference into the token store.</summary>
public sealed class OpaqueTokenFormat : ITokenFormat
{
    /// <inheritdoc />
    public ValueTask<string> CreateTokenAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)));
}

/// <summary>
/// Issues access tokens as signed JWTs (compact JWS, <c>typ: gnap-at+jwt</c>) with
/// the claims <c>iss</c>, <c>jti</c>, <c>iat</c>, <c>exp</c>, <c>access</c>,
/// <c>instance_id</c>, <c>sub</c> and, for key-bound tokens, <c>cnf.jkt</c>
/// (the RFC 7638 thumbprint of the bound key). Signed with the AS key given to the
/// constructor (ES256, ES384, EdDSA, PS512 or RS256 depending on the JWK).
/// </summary>
public sealed class JwtTokenFormat : ITokenFormat
{
    /// <summary>The JWT <c>typ</c> header value.</summary>
    public const string TokenType = "gnap-at+jwt";

    private readonly SignatureAlgorithm _algorithm;
    private readonly string _jwsAlgorithm;
    private readonly string? _keyId;

    /// <summary>Creates the format from the AS's private signing key.</summary>
    /// <exception cref="GnapException">The JWK has no private key or an unsupported key type.</exception>
    public JwtTokenFormat(JsonWebKey signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        if (!signingKey.HasPrivateKey)
        {
            throw new GnapException("The JWT signing key must contain private key material.");
        }

        _algorithm = signingKey.ToSignatureAlgorithm();
        _jwsAlgorithm = ToJwsAlgorithm(_algorithm.Name);
        _keyId = signingKey.Kid;
        PublicKey = signingKey.ToPublicKey();
    }

    /// <summary>The public verification key, e.g. for publishing to resource servers.</summary>
    public JsonWebKey PublicKey { get; }

    /// <inheritdoc />
    public ValueTask<string> CreateTokenAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        var header = Encode(writer =>
        {
            writer.WriteString("alg", _jwsAlgorithm);
            writer.WriteString("typ", TokenType);
            if (_keyId is not null)
            {
                writer.WriteString("kid", _keyId);
            }
        });

        var payload = Encode(writer =>
        {
            writer.WriteString("iss", descriptor.Issuer);
            writer.WriteString("jti", descriptor.TokenId);
            writer.WriteNumber("iat", descriptor.IssuedAt.ToUnixTimeSeconds());
            if (descriptor.ExpiresAt is { } expiresAt)
            {
                writer.WriteNumber("exp", expiresAt.ToUnixTimeSeconds());
            }

            if (descriptor.ResourceOwner is { } subject)
            {
                writer.WriteString("sub", subject);
            }

            if (descriptor.InstanceId is { } instanceId)
            {
                writer.WriteString("instance_id", instanceId);
            }

            writer.WritePropertyName("access");
            JsonSerializer.Serialize(writer, descriptor.Access, GnapJsonContext.Default.IListAccessRight);
            if (descriptor.BoundKey?.Jwk is { } jwk)
            {
                writer.WriteStartObject("cnf");
                writer.WriteString("jkt", jwk.ComputeThumbprint());
                writer.WriteEndObject();
            }
        });

        var signingInput = $"{header}.{payload}";
        var signature = _algorithm.Sign(Encoding.ASCII.GetBytes(signingInput));
        return ValueTask.FromResult($"{signingInput}.{Base64Url.EncodeToString(signature)}");
    }

    private static string Encode(Action<Utf8JsonWriter> writeMembers)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writeMembers(writer);
            writer.WriteEndObject();
        }

        return Base64Url.EncodeToString(buffer.ToArray());
    }

    private static string ToJwsAlgorithm(string httpSignatureAlgorithm) => httpSignatureAlgorithm switch
    {
        "ecdsa-p256-sha256" => "ES256",
        "ecdsa-p384-sha384" => "ES384",
        "ed25519" => "EdDSA",
        "rsa-pss-sha512" => "PS512",
        "rsa-v1_5-sha256" => "RS256",
        _ => throw new GnapException($"The key algorithm '{httpSignatureAlgorithm}' cannot sign JWT access tokens."),
    };
}
