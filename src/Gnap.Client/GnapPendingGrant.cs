using Gnap.Client.Interaction;
using Gnap.Client.Tokens;
using Gnap.Core.Models;

namespace Gnap.Client;

/// <summary>
/// A grant in progress: the state the client instance needs between the initial
/// grant response and the final tokens — the continuation URI and its rotating
/// access token, the <c>wait</c> time, and the nonces for verifying the
/// interaction finish hash (RFC 9635 Sections 3.1, 4.2.3 and 5).
/// Web applications keep this object between redirecting the user and
/// receiving the finish callback.
/// </summary>
public sealed class GnapPendingGrant
{
    private readonly GnapClient _client;
    private readonly InteractFinish? _finish;
    private readonly string? _asFinishNonce;
    private DateTimeOffset _notBefore;
    private TimeSpan _wait;
    private bool _callbackConsumed;

    internal GnapPendingGrant(GnapClient client, GnapClientKey key, Uri grantEndpoint, InteractFinish? finish, GrantResponse response)
    {
        _client = client;
        Key = key;
        GrantEndpoint = grantEndpoint;
        _finish = finish;
        _asFinishNonce = response.Interact?.Finish;
        Response = response;
        var now = client.Options.TimeProvider.GetUtcNow();
        Interaction = response.Interact is { } interact ? new GnapInteraction(interact, finish, now) : null;
        Accept(response, now);
    }

    /// <summary>The grant endpoint the grant request was sent to (the AS identifier of the finish hash).</summary>
    public Uri GrantEndpoint { get; }

    /// <summary>The client key the grant is bound to; it signs every continuation call.</summary>
    public GnapClientKey Key { get; }

    /// <summary>The most recent response from the AS.</summary>
    public GrantResponse Response { get; private set; }

    /// <summary>The current continuation information (URI and the latest continuation access token).</summary>
    public ContinueResponse? Continue => Response.Continue;

    /// <summary>The interaction requested by the AS in its initial response, if any.</summary>
    public GnapInteraction? Interaction { get; }

    /// <summary>The <c>nonce</c> the client sent in <c>interact.finish</c>, if it requested a finish callback.</summary>
    public string? ClientNonce => _finish?.Nonce;

    /// <summary>
    /// Whether the grant needs no further continuation: tokens or subject
    /// information were issued, or the AS offered no way to continue.
    /// </summary>
    public bool IsCompleted =>
        Response.AccessToken is { Count: > 0 } || Response.Subject is not null || Response.Continue is null;

    /// <summary>The earliest time the continuation URI may be called again (<c>wait</c>, RFC 9635 Section 3.1).</summary>
    public DateTimeOffset NextContinuationAllowedAt => _notBefore;

    /// <summary>
    /// Finishes the grant with the outcome of the interaction: verifies a finish
    /// callback's hash and continues with its <c>interact_ref</c> (falling back to
    /// polling if the AS is not done yet), or polls.
    /// </summary>
    /// <exception cref="GnapInteractionException">The callback is incomplete, replayed or its hash does not verify.</exception>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error, e.g. <c>user_denied</c>.</exception>
    public async Task<GnapGrantResult> CompleteAsync(GnapInteractionOutcome outcome, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(outcome);
        if (outcome.Failure is { } failure)
        {
            throw new GnapInteractionException(failure);
        }

        if (outcome.Callback is not { } callback)
        {
            return await PollAsync(cancellationToken).ConfigureAwait(false);
        }

        VerifyCallback(callback);
        _callbackConsumed = true;
        await ContinueOnceAsync(callback.InteractRef, cancellationToken).ConfigureAwait(false);
        return IsCompleted
            ? ToResult()
            : await PollAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Completes the grant from the URI the browser was redirected to (redirect finish method).</summary>
    /// <exception cref="GnapInteractionException">The callback is incomplete, replayed or its hash does not verify.</exception>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    public Task<GnapGrantResult> CompleteWithRedirectAsync(Uri redirectUri, CancellationToken cancellationToken = default) =>
        CompleteAsync(GnapInteractionOutcome.FromRedirect(redirectUri), cancellationToken);

    /// <summary>Completes the grant from the JSON body the AS pushed to the client (push finish method).</summary>
    /// <exception cref="GnapInteractionException">The callback is incomplete, replayed or its hash does not verify.</exception>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    public Task<GnapGrantResult> CompleteWithPushAsync(string pushBody, CancellationToken cancellationToken = default) =>
        CompleteAsync(GnapInteractionOutcome.FromPush(pushBody), cancellationToken);

    /// <summary>
    /// Polls the continuation URI (RFC 9635 Section 5.2) until the grant completes,
    /// respecting <c>wait</c> and backing off exponentially on <c>too_fast</c>.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error, e.g. <c>user_denied</c>.</exception>
    /// <exception cref="GnapClientException">Polling exceeded <see cref="GnapClientOptions.MaxPollingDuration"/>.</exception>
    public async Task<GnapGrantResult> PollAsync(CancellationToken cancellationToken = default)
    {
        var options = _client.Options;
        var deadline = options.TimeProvider.GetUtcNow() + options.MaxPollingDuration;
        while (!IsCompleted)
        {
            if (Max(_notBefore, options.TimeProvider.GetUtcNow()) > deadline)
            {
                throw new GnapClientException(
                    $"The grant was not completed within the polling limit of {options.MaxPollingDuration}.");
            }

            try
            {
                await ContinueOnceAsync(null, cancellationToken).ConfigureAwait(false);
            }
            catch (GnapProtocolException e) when (e.Code == GnapErrorCode.TooFast)
            {
                // Back off: double the interval (bounded) and keep the continuation
                // state, adopting a new one if the error response carries it.
                var now = options.TimeProvider.GetUtcNow();
                if (e.Response.Continue is { } continuation)
                {
                    Response = new GrantResponse { Continue = continuation };
                }

                var doubled = _wait * 2;
                _wait = doubled < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1)
                    : doubled > options.MaxPollingInterval ? options.MaxPollingInterval
                    : doubled;
                _notBefore = now + _wait;
            }
        }

        return ToResult();
    }

    /// <summary>
    /// Makes a single continuation call, first waiting until
    /// <see cref="NextContinuationAllowedAt"/>, and adopts the new continuation state.
    /// </summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    public async Task<GrantResponse> ContinueOnceAsync(string? interactRef, CancellationToken cancellationToken = default)
    {
        var continuation = Response.Continue
            ?? throw new GnapClientException("The AS offered no continuation for this grant.");
        var timeProvider = _client.Options.TimeProvider;
        var delay = _notBefore - timeProvider.GetUtcNow();
        if (delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, timeProvider, cancellationToken).ConfigureAwait(false);
        }

        var response = await _client.Protocol
            .ContinueGrantAsync(continuation, interactRef, Key, cancellationToken)
            .ConfigureAwait(false);
        Accept(response, timeProvider.GetUtcNow());
        return response;
    }

    /// <summary>Revokes the pending grant at the AS (RFC 9635 Section 5.4).</summary>
    /// <exception cref="GnapProtocolException">The AS returned a GNAP error.</exception>
    public Task CancelAsync(CancellationToken cancellationToken = default)
    {
        var continuation = Response.Continue
            ?? throw new GnapClientException("The AS offered no continuation for this grant.");
        return _client.Protocol.CancelGrantAsync(continuation, Key, cancellationToken);
    }

    /// <summary>The result of the completed grant.</summary>
    /// <exception cref="GnapClientException">The grant is not completed yet.</exception>
    public GnapGrantResult ToResult()
    {
        if (!IsCompleted)
        {
            throw new GnapClientException("The grant is still pending.");
        }

        var now = _client.Options.TimeProvider.GetUtcNow();
        var tokens = Response.AccessToken?
            .Select(t => GnapAccessToken.FromResponse(t, Key, now))
            .ToArray() ?? [];
        return new GnapGrantResult(Response, tokens);
    }

    private void VerifyCallback(InteractionFinishCallback callback)
    {
        if (_finish?.Nonce is not { } clientNonce)
        {
            throw new GnapInteractionException("The grant request did not ask for a finish callback; a callback cannot be accepted.");
        }

        if (_asFinishNonce is null)
        {
            throw new GnapInteractionException("The AS returned no 'interact.finish' nonce; the finish callback cannot be verified.");
        }

        if (_callbackConsumed)
        {
            throw new GnapInteractionException("A finish callback was already processed for this grant.");
        }

        if (!callback.VerifyHash(clientNonce, _asFinishNonce, GrantEndpoint.AbsoluteUri, _finish.HashMethod))
        {
            throw new GnapInteractionException("The interaction finish hash does not match; the callback is rejected.");
        }
    }

    private void Accept(GrantResponse response, DateTimeOffset now)
    {
        // A continuation response without a new 'continue' (e.g. the final token
        // response) keeps nothing to continue with; one with it replaces the
        // continuation access token, which the AS may rotate on every call.
        Response = response;
        if (response.Continue is { } continuation)
        {
            _wait = continuation.EffectiveWait;
            _notBefore = now + _wait;
        }
    }

    private static DateTimeOffset Max(DateTimeOffset a, DateTimeOffset b) => a > b ? a : b;
}
