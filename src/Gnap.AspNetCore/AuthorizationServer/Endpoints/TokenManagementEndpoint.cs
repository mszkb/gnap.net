using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>
/// The token management endpoints (RFC 9635 Section 6) at <c>{BasePath}/token/{manageId}</c>:
/// <c>POST</c> rotates the token (optionally binding it to a new key), <c>DELETE</c> revokes it.
/// </summary>
internal sealed class TokenManagementEndpoint(
    ITokenStore tokenStore,
    GrantIssuer issuer,
    KeyProofVerifier proofVerifier,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<TokenManagementEndpoint> logger)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public async Task RotateAsync(HttpContext context)
    {
        var (token, body) = await AuthenticateAsync(context, GnapErrorCode.InvalidRotation).ConfigureAwait(false);
        if (token is null)
        {
            return;
        }

        var boundKey = token.BoundKey;
        var managementKey = token.ManagementKey;
        if (body!.Length > 0)
        {
            // Key rotation (Section 6.1.2): the request carries the new key and is
            // signed by the current key and by the new key, the latter covering the former.
            if (!_options.AllowKeyRotation)
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.KeyRotationNotSupported).ConfigureAwait(false);
                return;
            }

            var newKey = ReadNewKey(body);
            if (newKey is null
                || newKey.IsReference
                || newKey.Jwk is null
                || newKey.Jwk.HasPrivateKey
                || !KeyProofVerifier.HasCoveringSignature(context)
                || !await proofVerifier.VerifyAsync(context, body, newKey, "key rotation (new key)").ConfigureAwait(false))
            {
                await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRotation).ConfigureAwait(false);
                return;
            }

            boundKey = token.IsBearer ? null : newKey;
            managementKey = newKey;
        }

        // Rotation is single-use: only the request that revokes the old token gets a new one.
        if (!await tokenStore.RevokeAsync(token.Id, context.RequestAborted).ConfigureAwait(false))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRotation).ConfigureAwait(false);
            return;
        }

        var lifetime = token.ExpiresAt is { } expiresAt ? expiresAt - token.IssuedAt : (TimeSpan?)null;
        var (_, rotated) = await issuer.IssueAsync(
            context,
            token.GrantId,
            token.Issuer ?? string.Empty,
            token.Access,
            token.Label,
            boundKey,
            managementKey,
            token.InstanceId,
            token.ResourceOwner,
            lifetime).ConfigureAwait(false);
        await Protocol.WriteAsync(context, StatusCodes.Status200OK, new GrantResponse { AccessToken = [rotated] }).ConfigureAwait(false);
    }

    public async Task RevokeAsync(HttpContext context)
    {
        var (token, _) = await AuthenticateAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
        if (token is null)
        {
            return;
        }

        await tokenStore.RevokeAsync(token.Id, context.RequestAborted).ConfigureAwait(false);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    private async Task<(TokenRecord? Token, byte[]? Body)> AuthenticateAsync(HttpContext context, GnapErrorCode failure)
    {
        var manageId = context.Request.RouteValues["manageId"] as string;
        var presented = Protocol.GetGnapToken(context);
        var token = manageId is null ? null : await tokenStore.FindByManageIdAsync(manageId, context.RequestAborted).ConfigureAwait(false);
        if (token is null || token.Revoked || !Protocol.MatchesHash(presented, token.ManageTokenHash))
        {
            logger.LogWarning("Rejected token management request: unknown, revoked or unauthenticated token.");
            await Protocol.WriteErrorAsync(context, failure, StatusCodes.Status401Unauthorized).ConfigureAwait(false);
            return (null, null);
        }

        var body = await Protocol.ReadBodyAsync(context, _options.MaxRequestBodySize).ConfigureAwait(false);
        if (body is null)
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidRequest).ConfigureAwait(false);
            return (null, null);
        }

        if (!await proofVerifier.VerifyAsync(context, body, token.ManagementKey, "token management").ConfigureAwait(false))
        {
            await Protocol.WriteErrorAsync(context, GnapErrorCode.InvalidClient).ConfigureAwait(false);
            return (null, null);
        }

        return (token, body);
    }

    private static GnapKey? ReadNewKey(byte[] body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return document.RootElement.ValueKind == JsonValueKind.Object
                   && document.RootElement.TryGetProperty("key", out var key)
                ? key.Deserialize(GnapJsonContext.Default.GnapKey)
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
