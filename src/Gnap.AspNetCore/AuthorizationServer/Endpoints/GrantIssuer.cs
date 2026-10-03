using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Endpoints;

/// <summary>Issues access tokens and continuation tokens, and finalizes approved grants.</summary>
internal sealed class GrantIssuer(
    ITokenFormat tokenFormat,
    ITokenStore tokenStore,
    IClientKeyStore clientKeyStore,
    GnapEndpointUris uris,
    IOptions<GnapAuthorizationServerOptions> options)
{
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    private DateTimeOffset Now => _options.TimeProvider.GetUtcNow();

    /// <summary>
    /// Finalizes an <see cref="GrantState.Approved"/> grant: issues its tokens,
    /// assigns an instance identifier if configured, rotates the continuation token
    /// (kept for grant revocation) and builds the response. The caller persists the grant.
    /// </summary>
    public async Task<(GrantResponse Response, IReadOnlyList<string> TokenIds)> FinalizeAsync(HttpContext context, GrantRecord grant)
    {
        var approval = grant.Approval ?? new Policy.GrantApproval();
        var requested = grant.Request.AccessToken ?? [];
        var issuer = grant.GrantEndpointUri;

        var newInstanceId = default(string);
        if (grant.InstanceId is null && _options.IssueInstanceIds)
        {
            newInstanceId = Protocol.NewSecret(16);
            await clientKeyStore.RegisterInstanceAsync(
                new ClientRegistration
                {
                    InstanceId = newInstanceId,
                    Key = grant.ClientKey,
                    ClassId = grant.ClientClassId,
                    Display = grant.ClientDisplay,
                },
                context.RequestAborted).ConfigureAwait(false);
            grant.InstanceId = newInstanceId;
        }

        var tokens = new List<AccessTokenResponse>(requested.Count);
        var tokenIds = new List<string>(requested.Count);
        for (var i = 0; i < requested.Count; i++)
        {
            var request = requested[i];
            var access = approval.Access?[i] ?? request.Access ?? [];
            var (record, response) = await IssueAsync(
                context,
                grant.Id,
                issuer,
                access,
                request.Label,
                request.IsBearer ? null : grant.ClientKey,
                grant.ClientKey,
                grant.InstanceId,
                approval.ResourceOwner,
                approval.AccessTokenLifetime ?? _options.AccessTokenLifetime).ConfigureAwait(false);
            tokens.Add(response);
            tokenIds.Add(record.Id);
        }

        grant.TransitionTo(GrantState.Finalized);
        grant.Approval = approval;
        var continuation = RotateContinuation(context, grant, Now + _options.FinalizedGrantLifetime, includeWait: false);
        var grantResponse = new GrantResponse
        {
            AccessToken = tokens.Count > 0 ? tokens : null,
            Subject = grant.Request.Subject is not null ? approval.Subject : null,
            InstanceId = newInstanceId,
            Continue = continuation,
        };
        return (grantResponse, tokenIds);
    }

    /// <summary>Issues (and stores) one access token.</summary>
    public async Task<(TokenRecord Record, AccessTokenResponse Response)> IssueAsync(
        HttpContext context,
        string grantId,
        string issuer,
        IList<AccessRight> access,
        string? label,
        GnapKey? boundKey,
        GnapKey managementKey,
        string? instanceId,
        string? resourceOwner,
        TimeSpan? lifetime)
    {
        var now = Now;
        var tokenId = Protocol.NewSecret(16);
        var expiresAt = lifetime is { } span ? now + span : (DateTimeOffset?)null;
        var value = await tokenFormat.CreateTokenAsync(
            new AccessTokenDescriptor
            {
                TokenId = tokenId,
                GrantId = grantId,
                Issuer = issuer,
                Access = access,
                BoundKey = boundKey,
                IssuedAt = now,
                ExpiresAt = expiresAt,
                InstanceId = instanceId,
                ResourceOwner = resourceOwner,
            },
            context.RequestAborted).ConfigureAwait(false);

        string? manageId = null;
        string? manageToken = null;
        if (_options.EnableTokenManagement)
        {
            manageId = Protocol.NewSecret(16);
            manageToken = Protocol.NewSecret();
        }

        var record = new TokenRecord
        {
            Id = tokenId,
            GrantId = grantId,
            ValueHash = Protocol.Hash(value),
            Access = access,
            Label = label,
            BoundKey = boundKey,
            ManagementKey = managementKey,
            ManageId = manageId,
            ManageTokenHash = manageToken is null ? null : Protocol.Hash(manageToken),
            IssuedAt = now,
            ExpiresAt = expiresAt,
            InstanceId = instanceId,
            ResourceOwner = resourceOwner,
            Issuer = issuer,
        };
        await tokenStore.StoreAsync(record, context.RequestAborted).ConfigureAwait(false);

        var response = new AccessTokenResponse
        {
            Value = value,
            Label = label,
            Access = access,
            ExpiresIn = lifetime is { } seconds ? (long)seconds.TotalSeconds : null,
            Flags = boundKey is null ? [AccessTokenFlags.Bearer] : null,
            Manage = manageId is null
                ? null
                : new TokenManagement
                {
                    Uri = uris.Token(context, manageId),
                    AccessToken = new AccessTokenResponse { Value = manageToken },
                },
        };
        return (record, response);
    }

    /// <summary>Issues a fresh continuation access token for the grant, invalidating the previous one.</summary>
    public ContinueResponse RotateContinuation(HttpContext context, GrantRecord grant, DateTimeOffset expiresAt, bool includeWait = true)
    {
        var token = Protocol.NewSecret();
        grant.ContinuationTokenHash = Protocol.Hash(token);
        grant.ContinuationExpiresAt = expiresAt;
        grant.NotBefore = includeWait ? Now + TimeSpan.FromSeconds(_options.ContinueWaitSeconds) : null;
        return new ContinueResponse
        {
            Uri = uris.Continue(context, grant.Id),
            Wait = includeWait ? _options.ContinueWaitSeconds : null,
            AccessToken = new AccessTokenResponse { Value = token },
        };
    }
}
