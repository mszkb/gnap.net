using System.Buffers.Text;
using System.Security.Cryptography;
using Gnap.Client.Discovery;
using Gnap.Client.Interaction;
using Gnap.Client.Tokens;
using Gnap.Core;
using Gnap.Core.Models;

namespace Gnap.Client;

/// <summary>
/// The high-level GNAP client (RFC 9635): requests access from an AS, drives the
/// interaction, continues or polls the grant, and manages the issued tokens.
/// Every request to the AS is signed with the client instance's key
/// (<c>httpsig</c>). Use <see cref="Protocol"/> for single protocol calls.
/// </summary>
/// <example>
/// <code>
/// var client = new GnapClient(httpClient, new GnapClientOptions
/// {
///     GrantEndpoint = new Uri("https://as.example/tx"),
///     ClientKey = GnapClientKey.FromJwk(privateJwk),
/// });
/// var result = await client.RequestAccessAsync(
///     new GrantRequest { AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("read")] }] },
///     GnapInteractionHandler.UserCode((i, _) => { Console.WriteLine(i.UserCode); return ValueTask.CompletedTask; }));
/// </code>
/// </example>
public sealed class GnapClient
{
    /// <summary>The name of the <see cref="HttpClient"/> registered by <c>AddGnapClient</c>.</summary>
    public const string HttpClientName = "Gnap.Client";

    /// <summary>Creates a client.</summary>
    /// <param name="httpClient">The HTTP client for all AS requests (not disposed by this class).</param>
    /// <param name="options">The client configuration.</param>
    /// <param name="metadataCache">A shared discovery cache; a private one when <see langword="null"/>.</param>
    public GnapClient(HttpClient httpClient, GnapClientOptions options, GnapMetadataCache? metadataCache = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
        Protocol = new GnapProtocolClient(httpClient, options);
        Discovery = new GnapDiscoveryClient(
            httpClient,
            metadataCache ?? new GnapMetadataCache(options.TimeProvider),
            options.MetadataCacheDuration);
    }

    /// <summary>The client configuration.</summary>
    public GnapClientOptions Options { get; }

    /// <summary>The low-level protocol calls.</summary>
    public GnapProtocolClient Protocol { get; }

    /// <summary>AS discovery with metadata caching.</summary>
    public GnapDiscoveryClient Discovery { get; }

    /// <summary>The client instance's current key.</summary>
    /// <exception cref="InvalidOperationException">No key is configured.</exception>
    public GnapClientKey ClientKey =>
        Options.ClientKey ?? throw new InvalidOperationException("GnapClientOptions.ClientKey is not configured.");

    /// <summary>The configured grant endpoint.</summary>
    /// <exception cref="InvalidOperationException">No grant endpoint is configured.</exception>
    public Uri GrantEndpoint =>
        Options.GrantEndpoint ?? throw new InvalidOperationException("GnapClientOptions.GrantEndpoint is not configured.");

    /// <summary>
    /// Switches the client instance to a new key for all future grant requests
    /// (client key rotation). Tokens already bound to the old key are moved with
    /// <see cref="RotateTokenKeyAsync"/> or <see cref="GnapTokenSource.RotateKeyAsync"/>.
    /// The options object is updated, so clients sharing it switch too.
    /// </summary>
    public void UseClientKey(GnapClientKey newKey)
    {
        ArgumentNullException.ThrowIfNull(newKey);
        Options.ClientKey = newKey;
    }

    /// <summary>Discovers the configured AS (RFC 9635 Section 9) via its grant endpoint, cached.</summary>
    /// <exception cref="GnapClientException">Discovery failed.</exception>
    public Task<AuthorizationServerMetadata> DiscoverAsync(CancellationToken cancellationToken = default) =>
        Discovery.GetGrantEndpointMetadataAsync(GrantEndpoint, cancellationToken);

    /// <summary>
    /// Requests access and drives the grant to completion: shows the interaction
    /// through <paramref name="interactionHandler"/> when the AS requires one,
    /// verifies the finish callback, then continues or polls until tokens are issued.
    /// </summary>
    /// <param name="request">
    /// The grant request. A missing <c>client</c> is filled from the options; a missing
    /// <c>interact</c> comes from the handler; finish nonces are generated.
    /// </param>
    /// <param name="interactionHandler">Shows the interaction to the user; required when the AS asks for interaction.</param>
    /// <param name="cancellationToken">Cancels the flow, including waits and polling.</param>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error, e.g. <c>user_denied</c>.</exception>
    /// <exception cref="GnapInteractionException">The finish callback failed verification.</exception>
    /// <exception cref="GnapClientException">The AS was unreachable, answered unexpectedly, or polling timed out.</exception>
    public async Task<GnapGrantResult> RequestAccessAsync(
        GrantRequest request,
        IGnapInteractionHandler? interactionHandler = null,
        CancellationToken cancellationToken = default)
    {
        var pending = await StartGrantAsync(request, interactionHandler, cancellationToken).ConfigureAwait(false);
        if (pending.IsCompleted)
        {
            return pending.ToResult();
        }

        if (pending.Interaction is { } interaction)
        {
            if (interactionHandler is null)
            {
                throw new GnapClientException("The AS requires interaction, but no interaction handler was supplied.");
            }

            var outcome = await interactionHandler.InteractAsync(interaction, cancellationToken).ConfigureAwait(false);
            return await pending.CompleteAsync(outcome, cancellationToken).ConfigureAwait(false);
        }

        return await pending.PollAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Requests a single access token for the given rights; see <see cref="RequestAccessAsync(GrantRequest, IGnapInteractionHandler?, CancellationToken)"/>.</summary>
    public Task<GnapGrantResult> RequestAccessAsync(
        IEnumerable<AccessRight> access,
        IGnapInteractionHandler? interactionHandler = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(access);
        return RequestAccessAsync(
            new GrantRequest { AccessToken = [new AccessTokenRequest { Access = [.. access] }] },
            interactionHandler,
            cancellationToken);
    }

    /// <summary>
    /// Sends the grant request (RFC 9635 Section 2) and returns the pending grant
    /// without driving the interaction — for web applications that redirect the user
    /// and later complete the grant from the finish callback.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    /// <exception cref="GnapClientException">The AS was unreachable or answered unexpectedly.</exception>
    public async Task<GnapPendingGrant> StartGrantAsync(
        GrantRequest request,
        IGnapInteractionHandler? interactionHandler = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var key = ClientKey;
        var grantEndpoint = GrantEndpoint;
        var prepared = Prepare(request, interactionHandler, key);
        var response = await Protocol.RequestGrantAsync(grantEndpoint, prepared, key, cancellationToken).ConfigureAwait(false);
        return new GnapPendingGrant(this, key, grantEndpoint, prepared.Interact?.Finish, response);
    }

    /// <summary>
    /// Rotates an access token (RFC 9635 Section 6.1.1) — GNAP's refresh — and
    /// returns its replacement. The old value must no longer be used.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS refused the rotation.</exception>
    /// <exception cref="GnapClientException">The token offers no management.</exception>
    public async Task<GnapAccessToken> RotateTokenAsync(GnapAccessToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        var rotated = await Protocol.RotateTokenAsync(token.Token, token.ManagementKey, cancellationToken).ConfigureAwait(false);
        var boundKey = rotated.IsBoundToClientKey ? token.ManagementKey : null;
        return token.WithRotated(rotated, boundKey, token.ManagementKey, Options.TimeProvider.GetUtcNow());
    }

    /// <summary>
    /// Binds an access token to a new key (RFC 9635 Section 6.1.2), proving
    /// possession of both the current and the new key.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS refused, e.g. <c>key_rotation_not_supported</c>.</exception>
    /// <exception cref="GnapClientException">The token offers no management.</exception>
    public async Task<GnapAccessToken> RotateTokenKeyAsync(
        GnapAccessToken token,
        GnapClientKey newKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(newKey);
        var currentKey = token.BoundKey ?? token.ManagementKey;
        var rotated = await Protocol.RotateTokenKeyAsync(token.Token, currentKey, newKey, cancellationToken).ConfigureAwait(false);
        return token.WithRotated(rotated, rotated.IsBearer ? null : newKey, newKey, Options.TimeProvider.GetUtcNow());
    }

    /// <summary>Revokes an access token (RFC 9635 Section 6.2).</summary>
    /// <exception cref="GnapProtocolException">The AS refused the revocation.</exception>
    /// <exception cref="GnapClientException">The token offers no management.</exception>
    public Task RevokeTokenAsync(GnapAccessToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);
        return Protocol.RevokeTokenAsync(token.Token, token.ManagementKey, cancellationToken);
    }

    /// <summary>Creates a self-refreshing holder for the token, e.g. for <see cref="GnapAccessTokenHandler"/>.</summary>
    public GnapTokenSource CreateTokenSource(GnapAccessToken token) => new(this, token);

    private GrantRequest Prepare(GrantRequest request, IGnapInteractionHandler? handler, GnapClientKey key)
    {
        var interact = request.Interact ?? handler?.CreateInteractRequest();
        if (interact?.Finish is { } finish)
        {
            if (string.IsNullOrEmpty(finish.Method) || string.IsNullOrEmpty(finish.Uri))
            {
                throw new GnapClientException("interact.finish requires a 'method' and a 'uri'.");
            }

            var hashMethod = finish.HashMethod ?? Options.FinishHashMethod;
            if (hashMethod is not null && !InteractionFinishHash.IsSupported(hashMethod))
            {
                throw new GnapClientException($"The finish hash method '{hashMethod}' is not supported on this platform.");
            }

            interact = new InteractRequest
            {
                Start = interact.Start,
                Hints = interact.Hints,
                Finish = new InteractFinish
                {
                    Method = finish.Method,
                    Uri = finish.Uri,
                    Nonce = string.IsNullOrEmpty(finish.Nonce) ? NewNonce() : finish.Nonce,
                    HashMethod = hashMethod,
                },
            };
        }

        return new GrantRequest
        {
            AccessToken = request.AccessToken,
            Subject = request.Subject,
            Client = request.Client ?? CreateClientInstance(key),
            User = request.User,
            Interact = interact,
            AdditionalFields = request.AdditionalFields,
        };
    }

    private ClientInstance CreateClientInstance(GnapClientKey key) =>
        Options.InstanceId is { } instanceId
            ? ClientInstance.ForReference(instanceId)
            : new ClientInstance { Key = key.PresentedKey, ClassId = Options.ClassId, Display = Options.Display };

    private static string NewNonce() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(24));
}
