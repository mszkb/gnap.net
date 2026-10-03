using System.Text.Json;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>
/// What the resource server knows about an active access token: the fields of an
/// RFC 9767 introspection response (Section 3.3), whichever way the token was
/// validated (introspection, the co-hosted AS's token store, or a self-contained JWT).
/// </summary>
public sealed class GnapTokenInfo
{
    /// <summary>The rights of access the token carries.</summary>
    public IList<AccessRight> Access { get; init; } = [];

    /// <summary>
    /// The key the token is bound to (with its proof method); <see langword="null"/>
    /// only for bearer tokens. Every request presenting a key-bound token must carry
    /// a valid key proof by this key.
    /// </summary>
    public GnapKey? Key { get; init; }

    /// <summary>The token flags (e.g. <c>bearer</c>).</summary>
    public IList<string> Flags { get; init; } = [];

    /// <summary>
    /// Whether the token is a bearer token: the AS flagged it <c>bearer</c> and bound
    /// no key. A token without key and without the flag is not a bearer token and is
    /// rejected, so a missing key can never downgrade a bound token.
    /// </summary>
    public bool IsBearer => Key is null && Flags.Contains(AccessTokenFlags.Bearer);

    /// <summary>When the token was issued, if known.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>When the token expires, if it does.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>The issuing AS (its grant endpoint URI), if known.</summary>
    public string? Issuer { get; init; }

    /// <summary>The resource owner (subject) the grant was approved for, if known.</summary>
    public string? Subject { get; init; }

    /// <summary>The client instance identifier, if known.</summary>
    public string? InstanceId { get; init; }

    /// <summary>The token identifier (JWT <c>jti</c>), if known.</summary>
    public string? TokenId { get; init; }

    /// <summary>Whether the token has expired at <paramref name="now"/>.</summary>
    public bool IsExpired(DateTimeOffset now) => ExpiresAt is { } expiresAt && now >= expiresAt;

    /// <summary>
    /// Reads introspection-response-shaped JSON (also the claim set of a JWT issued
    /// by <see cref="AuthorizationServer.Tokens.JwtTokenFormat"/>).
    /// </summary>
    /// <returns><see langword="null"/> when <paramref name="requireActive"/> is set and the token is not active, or the JSON is malformed.</returns>
    internal static GnapTokenInfo? Parse(JsonElement root, bool requireActive)
    {
        if (root.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (requireActive && !(root.TryGetProperty("active", out var active) && active.ValueKind == JsonValueKind.True))
        {
            return null;
        }

        try
        {
            IList<AccessRight> access = [];
            if (root.TryGetProperty("access", out var accessElement))
            {
                if (accessElement.ValueKind != JsonValueKind.Array)
                {
                    return null;
                }

                access = accessElement.Deserialize(GnapJsonContext.Default.IListAccessRight) ?? [];
            }

            GnapKey? key = null;
            if (root.TryGetProperty("key", out var keyElement))
            {
                key = keyElement.ValueKind switch
                {
                    JsonValueKind.String => GnapKey.ForReference(keyElement.GetString()!),
                    JsonValueKind.Object => keyElement.Deserialize(GnapJsonContext.Default.GnapKey),
                    _ => null,
                };
                if (key is null)
                {
                    return null;
                }
            }

            var flags = new List<string>();
            if (root.TryGetProperty("flags", out var flagsElement))
            {
                if (flagsElement.ValueKind != JsonValueKind.Array)
                {
                    return null;
                }

                foreach (var flag in flagsElement.EnumerateArray())
                {
                    if (flag.ValueKind != JsonValueKind.String)
                    {
                        return null;
                    }

                    flags.Add(flag.GetString()!);
                }
            }

            return new GnapTokenInfo
            {
                Access = access,
                Key = key,
                Flags = flags,
                IssuedAt = ReadTime(root, "iat"),
                ExpiresAt = ReadTime(root, "exp"),
                Issuer = ReadString(root, "iss"),
                Subject = ReadString(root, "sub"),
                InstanceId = ReadString(root, "instance_id"),
                TokenId = ReadString(root, "jti"),
            };
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static DateTimeOffset? ReadTime(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}

/// <summary>
/// The <see cref="Microsoft.AspNetCore.Http.HttpContext"/> feature describing the
/// validated GNAP access token of the current request.
/// </summary>
public interface IGnapTokenFeature
{
    /// <summary>The validated token.</summary>
    GnapTokenInfo Token { get; }
}

internal sealed class GnapTokenFeature(GnapTokenInfo token) : IGnapTokenFeature
{
    public GnapTokenInfo Token { get; } = token;
}

/// <summary>Claim types of the principal created for a GNAP access token.</summary>
public static class GnapClaimTypes
{
    /// <summary>One claim per right of access, its value being the right's JSON (an object or a reference string).</summary>
    public const string Access = "gnap_access";

    /// <summary>The resource owner the grant was approved for.</summary>
    public const string Subject = "sub";

    /// <summary>The client instance identifier.</summary>
    public const string InstanceId = "instance_id";

    /// <summary>The issuing AS.</summary>
    public const string Issuer = "iss";
}
