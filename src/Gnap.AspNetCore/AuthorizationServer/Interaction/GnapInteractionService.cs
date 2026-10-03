using System.Text;
using Gnap.AspNetCore.AuthorizationServer.Endpoints;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Interaction;

/// <summary>
/// The API a consent UI uses to show and decide a pending interaction (RFC 9635
/// Section 4). Every call checks that the interaction is bound to the calling
/// browser session, is still pending and has not expired.
/// </summary>
public interface IGnapInteractionService
{
    /// <summary>
    /// Returns the pending interaction for display, or <see langword="null"/> when it
    /// is unknown, expired, already decided or bound to another browser session.
    /// </summary>
    Task<GnapInteractionContext?> GetInteractionAsync(HttpContext httpContext, string interactionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the RO's approval and finishes the interaction: for the <c>redirect</c>
    /// finish method the result carries the client callback URI to send the browser
    /// to; for <c>push</c> the AS has notified the client; without a finish method the
    /// client picks the result up by polling.
    /// </summary>
    /// <exception cref="ArgumentException">The approval's per-token access does not match the request.</exception>
    Task<GnapInteractionCompletion> ApproveAsync(HttpContext httpContext, string interactionId, GrantApproval approval, CancellationToken cancellationToken = default);

    /// <summary>Records the RO's denial and finishes the interaction; the client learns <c>user_denied</c>.</summary>
    Task<GnapInteractionCompletion> DenyAsync(HttpContext httpContext, string interactionId, CancellationToken cancellationToken = default);
}

/// <summary>A pending interaction as shown on a consent page.</summary>
public sealed class GnapInteractionContext
{
    /// <summary>The interaction identifier.</summary>
    public required string InteractionId { get; init; }

    /// <summary>The verified client identity.</summary>
    public required ClientIdentity Client { get; init; }

    /// <summary>The requested access tokens, in request order (approve per index).</summary>
    public required IReadOnlyList<AccessTokenRequest> AccessTokens { get; init; }

    /// <summary>The requested subject information, if any.</summary>
    public SubjectRequest? Subject { get; init; }

    /// <summary>The end user as known to the client, if sent.</summary>
    public RequestUser? User { get; init; }

    /// <summary>The client's interaction hints (e.g. <c>ui_locales</c>).</summary>
    public InteractHints? Hints { get; init; }

    /// <summary>When the interaction expires.</summary>
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>The outcome of deciding an interaction.</summary>
public sealed class GnapInteractionCompletion
{
    /// <summary>Whether the decision was recorded.</summary>
    public bool Succeeded { get; init; }

    /// <summary>The client callback URI to redirect the browser to (<c>redirect</c> finish method).</summary>
    public Uri? RedirectUri { get; init; }

    /// <summary>Whether the finish message was delivered by <c>push</c>.</summary>
    public bool Pushed { get; init; }

    /// <summary>The result for an unknown, expired, foreign-session or already decided interaction.</summary>
    public static GnapInteractionCompletion Failed { get; } = new() { Succeeded = false };
}

/// <summary>The default <see cref="IGnapInteractionService"/>.</summary>
internal sealed class GnapInteractionService(
    IGrantStore grantStore,
    IHttpClientFactory httpClientFactory,
    IOptions<GnapAuthorizationServerOptions> options,
    ILogger<GnapInteractionService> logger) : IGnapInteractionService
{
    private const string CookiePrefix = "gnap.ix.";
    private readonly GnapAuthorizationServerOptions _options = options.Value;

    public async Task<GnapInteractionContext?> GetInteractionAsync(HttpContext httpContext, string interactionId, CancellationToken cancellationToken = default)
    {
        var grant = await FindPendingAsync(interactionId, cancellationToken).ConfigureAwait(false);
        if (grant is null || !IsBoundTo(httpContext, grant))
        {
            return null;
        }

        return new GnapInteractionContext
        {
            InteractionId = interactionId,
            Client = new ClientIdentity
            {
                Key = grant.ClientKey,
                KeyThumbprint = grant.ClientKey.Jwk!.ComputeThumbprint(),
                InstanceId = grant.InstanceId,
                ClassId = grant.ClientClassId,
                Display = grant.ClientDisplay,
                IsRegistered = grant.ClientIsRegistered,
            },
            AccessTokens = [.. grant.Request.AccessToken ?? []],
            Subject = grant.Request.Subject,
            User = grant.Request.User,
            Hints = grant.Request.Interact?.Hints,
            ExpiresAt = grant.InteractionExpiresAt!.Value,
        };
    }

    public Task<GnapInteractionCompletion> ApproveAsync(HttpContext httpContext, string interactionId, GrantApproval approval, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(approval);
        return CompleteAsync(httpContext, interactionId, cancellationToken, grant =>
        {
            if (!GrantEndpoint.ApprovalFits(approval, grant.Request))
            {
                throw new ArgumentException("GrantApproval.Access must contain one entry per requested access token.", nameof(approval));
            }

            grant.Approval = approval;
            grant.TransitionTo(GrantState.Approved);
        });
    }

    public Task<GnapInteractionCompletion> DenyAsync(HttpContext httpContext, string interactionId, CancellationToken cancellationToken = default) =>
        CompleteAsync(httpContext, interactionId, cancellationToken, grant =>
        {
            grant.DenialCode = GnapErrorCode.UserDenied.Value;
            grant.TransitionTo(GrantState.Revoked);
        });

    /// <summary>
    /// Binds a pending interaction to the calling browser (RFC 9635 Section 4.1): the
    /// first browser to open it receives a session cookie, and only that browser can
    /// continue it. Binding also consumes the user code.
    /// </summary>
    internal async Task<bool> BindSessionAsync(HttpContext httpContext, GrantRecord grant)
    {
        if (grant.InteractionSessionHash is not null)
        {
            return IsBoundTo(httpContext, grant);
        }

        var secret = Protocol.NewSecret();
        grant.InteractionSessionHash = Protocol.Hash(secret);
        grant.UserCode = null;
        if (!await grantStore.TryUpdateAsync(grant, httpContext.RequestAborted).ConfigureAwait(false))
        {
            return false;
        }

        httpContext.Response.Cookies.Append(CookiePrefix + grant.InteractionId, secret, new CookieOptions
        {
            HttpOnly = true,
            Secure = httpContext.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            IsEssential = true,
        });
        return true;
    }

    internal async Task<GrantRecord?> FindPendingAsync(string? interactionId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(interactionId))
        {
            return null;
        }

        var grant = await grantStore.FindByInteractionIdAsync(interactionId, cancellationToken).ConfigureAwait(false);
        return IsPending(grant) ? grant : null;
    }

    internal async Task<GrantRecord?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken)
    {
        var grant = await grantStore.FindByUserCodeAsync(userCode, cancellationToken).ConfigureAwait(false);
        return IsPending(grant) ? grant : null;
    }

    private bool IsPending(GrantRecord? grant) =>
        grant is { State: GrantState.Pending, InteractionExpiresAt: { } expiresAt } && _options.TimeProvider.GetUtcNow() < expiresAt;

    private static bool IsBoundTo(HttpContext httpContext, GrantRecord grant) =>
        Protocol.MatchesHash(httpContext.Request.Cookies[CookiePrefix + grant.InteractionId], grant.InteractionSessionHash);

    private async Task<GnapInteractionCompletion> CompleteAsync(
        HttpContext httpContext,
        string interactionId,
        CancellationToken cancellationToken,
        Action<GrantRecord> decide)
    {
        var grant = await FindPendingAsync(interactionId, cancellationToken).ConfigureAwait(false);
        if (grant is null || !IsBoundTo(httpContext, grant))
        {
            logger.LogWarning("Rejected interaction decision: unknown, expired, decided or foreign-session interaction.");
            return GnapInteractionCompletion.Failed;
        }

        decide(grant);

        InteractionFinishCallback? callback = null;
        if (grant.Finish is { } finish)
        {
            var interactRef = Protocol.NewSecret(16);
            grant.InteractRefHash = Protocol.Hash(interactRef);
            callback = new InteractionFinishCallback
            {
                InteractRef = interactRef,
                Hash = InteractionFinishHash.Compute(finish.Nonce!, grant.AsNonce!, interactRef, grant.GrantEndpointUri, finish.HashMethod),
            };
        }

        if (!await grantStore.TryUpdateAsync(grant, cancellationToken).ConfigureAwait(false))
        {
            return GnapInteractionCompletion.Failed;
        }

        httpContext.Response.Cookies.Delete(CookiePrefix + grant.InteractionId, new CookieOptions { Path = "/" });
        if (callback is null)
        {
            return new GnapInteractionCompletion { Succeeded = true };
        }

        var finishUri = grant.Finish!.Uri!;
        if (grant.Finish.Method == FinishMethods.Push)
        {
            return new GnapInteractionCompletion { Succeeded = true, Pushed = await PushAsync(finishUri, callback, cancellationToken).ConfigureAwait(false) };
        }

        return new GnapInteractionCompletion { Succeeded = true, RedirectUri = callback.ToRedirectUri(finishUri) };
    }

    private async Task<bool> PushAsync(string uri, InteractionFinishCallback callback, CancellationToken cancellationToken)
    {
        try
        {
            using var client = httpClientFactory.CreateClient(GnapAuthorizationServerOptions.PushHttpClientName);
            using var content = new StringContent(GnapJson.Serialize(callback), Encoding.UTF8, GnapConstants.MediaType);
            using var response = await client.PostAsync(new Uri(uri), content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("The interaction finish push to the client was answered with HTTP {Status}.", (int)response.StatusCode);
            }

            return response.IsSuccessStatusCode;
        }
        catch (HttpRequestException e)
        {
            logger.LogWarning("The interaction finish push to the client failed: {Reason}", e.Message);
            return false;
        }
    }
}
