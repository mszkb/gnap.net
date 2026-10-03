using System.Text;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>
/// Token introspection (RFC 9767 Section 3.3) at <c>POST {BasePath}/introspect</c>.
/// The calling RS identifies itself by reference in <c>resource_server</c> and must
/// sign the request (<c>httpsig</c>) with its registered key. Inactive, unknown,
/// expired and revoked tokens, and tokens presented with a mismatching proof
/// method or for rights they do not carry, all yield exactly <c>{"active": false}</c>.
/// </summary>
internal sealed class IntrospectionEndpoint(
    ITokenStore tokenStore,
    IResourceServerStore resourceServers,
    KeyProofVerifier proofVerifier,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<IntrospectionEndpoint> logger)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public async Task HandleAsync(HttpContext context)
    {
        var body = await Protocol.ReadBodyAsync(context, _options.MaxRequestBodySize).ConfigureAwait(false);
        if (body is null || !TryParse(body, out var request))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return;
        }

        var resourceServer = await resourceServers.FindAsync(request.ResourceServer, context.RequestAborted).ConfigureAwait(false);
        if (resourceServer is null
            || !await proofVerifier.VerifyAsync(context, body, resourceServer.Key, "introspection").ConfigureAwait(false))
        {
            logger.LogWarning("Rejected introspection: unknown or unauthenticated resource server.");
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidClient).ConfigureAwait(false);
            return;
        }

        var token = await tokenStore.FindByValueHashAsync(Protocol.Hash(request.AccessToken), context.RequestAborted).ConfigureAwait(false);
        var now = _options.TimeProvider.GetUtcNow();
        var active = token is not null
            && token.IsActive(now)
            && ProofMatches(token, request.Proof)
            && AccessCovered(token, request.Access);

        await Protocol.WriteJsonAsync(context, StatusCodes.Status200OK, active ? Describe(token!) : """{"active":false}""").ConfigureAwait(false);
    }

    private static bool ProofMatches(TokenRecord token, string? proof) =>
        proof is null
        || (token.IsBearer ? proof == AccessTokenFlags.Bearer : proof == token.BoundKey!.Proof?.Method);

    private static bool AccessCovered(TokenRecord token, IList<AccessRight>? requested)
    {
        if (requested is null)
        {
            return true;
        }

        var granted = token.Access.Select(a => JsonSerializer.Serialize(a, GnapJsonContext.Default.AccessRight)).ToHashSet(StringComparer.Ordinal);
        return requested.All(a => granted.Contains(JsonSerializer.Serialize(a, GnapJsonContext.Default.AccessRight)));
    }

    private static string Describe(TokenRecord token)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("active", true);
            writer.WritePropertyName("access");
            JsonSerializer.Serialize(writer, token.Access, GnapJsonContext.Default.IListAccessRight);
            if (token.BoundKey is { } key)
            {
                writer.WritePropertyName("key");
                JsonSerializer.Serialize(writer, key, GnapJsonContext.Default.GnapKey);
            }
            else
            {
                writer.WriteStartArray("flags");
                writer.WriteStringValue(AccessTokenFlags.Bearer);
                writer.WriteEndArray();
            }

            writer.WriteNumber("iat", token.IssuedAt.ToUnixTimeSeconds());
            if (token.ExpiresAt is { } expiresAt)
            {
                writer.WriteNumber("exp", expiresAt.ToUnixTimeSeconds());
            }

            if (token.Issuer is { } issuer)
            {
                writer.WriteString("iss", issuer);
            }

            if (token.InstanceId is { } instanceId)
            {
                writer.WriteString("instance_id", instanceId);
            }

            if (token.ResourceOwner is { } owner)
            {
                writer.WriteString("sub", owner);
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static bool TryParse(byte[] body, out IntrospectionRequest request)
    {
        request = default;
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("resource_server", out var rs) || rs.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            string? proof = null;
            if (root.TryGetProperty("proof", out var proofElement))
            {
                if (proofElement.ValueKind != JsonValueKind.String)
                {
                    return false;
                }

                proof = proofElement.GetString();
            }

            IList<AccessRight>? access = null;
            if (root.TryGetProperty("access", out var accessElement))
            {
                access = accessElement.Deserialize(GnapJsonContext.Default.IListAccessRight);
            }

            request = new IntrospectionRequest(accessToken.GetString()!, rs.GetString()!, proof, access);
            return request.AccessToken.Length > 0 && request.ResourceServer.Length > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private readonly record struct IntrospectionRequest(string AccessToken, string ResourceServer, string? Proof, IList<AccessRight>? Access);
}

/// <summary>
/// AS discovery (RFC 9635 Section 9 via <c>OPTIONS</c> on the grant endpoint, and
/// RFC 9767 Section 3.1 at <c>/.well-known/gnap-as-rs</c>).
/// </summary>
internal sealed class DiscoveryEndpoint(GnapEndpointUris uris, IOptions<GnapAuthorizationServerOptions> options)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public Task HandleAsync(HttpContext context)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("grant_request_endpoint", uris.GrantEndpoint(context));
            WriteArray(writer, "interaction_start_modes_supported", GrantEndpoint.SupportedStartModes);
            WriteArray(writer, "interaction_finish_methods_supported", GrantEndpoint.SupportedFinishMethods);
            WriteArray(writer, "key_proofs_supported", [Core.Keys.ProofMethod.Methods.HttpSig]);
            if (_options.SubjectIdFormatsSupported.Count > 0)
            {
                WriteArray(writer, "sub_id_formats_supported", _options.SubjectIdFormatsSupported);
            }

            writer.WriteBoolean("key_rotation_supported", _options.AllowKeyRotation && _options.EnableTokenManagement);
            if (_options.EnableIntrospection)
            {
                writer.WriteString("introspection_endpoint", uris.Introspection(context));
            }

            writer.WriteEndObject();
        }

        return Protocol.WriteJsonAsync(context, StatusCodes.Status200OK, Encoding.UTF8.GetString(buffer.ToArray()));
    }

    private static void WriteArray(Utf8JsonWriter writer, string name, IEnumerable<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values)
        {
            writer.WriteStringValue(value);
        }

        writer.WriteEndArray();
    }
}
