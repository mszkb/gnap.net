using Gnap.Core.Models;

namespace Gnap.Client.Interaction;

/// <summary>
/// Drives the end-user interaction of a grant on behalf of
/// <see cref="GnapClient.RequestAccessAsync(GrantRequest, IGnapInteractionHandler?, CancellationToken)"/>:
/// it declares how the client can interact and finish, then shows the
/// interaction to the user and hands back the finish callback (or asks to poll).
/// </summary>
public interface IGnapInteractionHandler
{
    /// <summary>
    /// The <c>interact</c> request to send when the grant request has none. The
    /// client fills in the finish <c>nonce</c> (and <c>hash_method</c>) itself.
    /// </summary>
    InteractRequest CreateInteractRequest();

    /// <summary>
    /// Shows the interaction to the end user (open the redirect URI, display the
    /// user code, ...) and returns the received finish callback, or
    /// <see cref="GnapInteractionOutcome.Poll"/> to poll the AS.
    /// </summary>
    ValueTask<GnapInteractionOutcome> InteractAsync(GnapInteraction interaction, CancellationToken cancellationToken);
}

/// <summary>Ready-made <see cref="IGnapInteractionHandler"/> implementations.</summary>
public static class GnapInteractionHandler
{
    /// <summary>
    /// A handler from an <c>interact</c> request and a delegate, e.g. one that opens
    /// the browser and awaits the redirect to a local callback endpoint.
    /// </summary>
    public static IGnapInteractionHandler Create(
        InteractRequest interact,
        Func<GnapInteraction, CancellationToken, ValueTask<GnapInteractionOutcome>> interactAsync)
    {
        ArgumentNullException.ThrowIfNull(interact);
        ArgumentNullException.ThrowIfNull(interactAsync);
        return new DelegateHandler(interact, interactAsync);
    }

    /// <summary>
    /// A redirect-start, redirect-finish handler (RFC 9635 Sections 2.5.1.1 and
    /// 2.5.2.1): <paramref name="interactAsync"/> sends the user to
    /// <see cref="GnapInteraction.RedirectUri"/> and returns the URI the browser
    /// came back to at <paramref name="callbackUri"/>.
    /// </summary>
    public static IGnapInteractionHandler Redirect(
        Uri callbackUri,
        Func<GnapInteraction, CancellationToken, ValueTask<Uri>> interactAsync)
    {
        ArgumentNullException.ThrowIfNull(callbackUri);
        ArgumentNullException.ThrowIfNull(interactAsync);
        return Create(
            new InteractRequest
            {
                Start = [new StartMode(StartModes.Redirect)],
                Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = callbackUri.AbsoluteUri },
            },
            async (interaction, cancellationToken) =>
                GnapInteractionOutcome.FromRedirect(await interactAsync(interaction, cancellationToken).ConfigureAwait(false)));
    }

    /// <summary>
    /// A device-style handler without a finish callback: requests the
    /// <c>user_code</c> and <c>user_code_uri</c> start modes, lets
    /// <paramref name="display"/> show the code, and polls the AS for the result.
    /// </summary>
    public static IGnapInteractionHandler UserCode(Func<GnapInteraction, CancellationToken, ValueTask> display)
    {
        ArgumentNullException.ThrowIfNull(display);
        return Create(
            new InteractRequest { Start = [new StartMode(StartModes.UserCodeUri), new StartMode(StartModes.UserCode)] },
            async (interaction, cancellationToken) =>
            {
                await display(interaction, cancellationToken).ConfigureAwait(false);
                return GnapInteractionOutcome.Poll;
            });
    }

    private sealed class DelegateHandler(
        InteractRequest interact,
        Func<GnapInteraction, CancellationToken, ValueTask<GnapInteractionOutcome>> interactAsync) : IGnapInteractionHandler
    {
        public InteractRequest CreateInteractRequest() => new()
        {
            Start = interact.Start is null ? null : [.. interact.Start],
            Hints = interact.Hints,
            Finish = interact.Finish is null
                ? null
                : new InteractFinish
                {
                    Method = interact.Finish.Method,
                    Uri = interact.Finish.Uri,
                    Nonce = interact.Finish.Nonce,
                    HashMethod = interact.Finish.HashMethod,
                },
        };

        public ValueTask<GnapInteractionOutcome> InteractAsync(GnapInteraction interaction, CancellationToken cancellationToken) =>
            interactAsync(interaction, cancellationToken);
    }
}
