using Gnap.Core.Models;

namespace Gnap.Client.Interaction;

/// <summary>
/// The interaction the AS asks for (RFC 9635 Section 3.3), in a form ready to
/// show to the end user: a URI to open in a browser, an app URI, or a user code
/// (with or without a short URI).
/// </summary>
public sealed class GnapInteraction
{
    internal GnapInteraction(InteractResponse response, InteractFinish? requestedFinish, DateTimeOffset receivedAt)
    {
        Response = response;
        FinishMethod = requestedFinish?.Method;
        FinishUri = requestedFinish?.Uri;
        RedirectUri = AbsoluteOrNull(response.Redirect);
        AppUri = AbsoluteOrNull(response.App);
        ExpiresAt = response.ExpiresIn is { } seconds ? receivedAt.AddSeconds(seconds) : null;
    }

    /// <summary>The raw interaction response.</summary>
    public InteractResponse Response { get; }

    /// <summary>The URI to send the end user to (<c>redirect</c> start mode).</summary>
    public Uri? RedirectUri { get; }

    /// <summary>The application URI to launch (<c>app</c> start mode).</summary>
    public Uri? AppUri { get; }

    /// <summary>The code to display for entry at a stable URI (<c>user_code</c> start mode).</summary>
    public string? UserCode => Response.UserCode;

    /// <summary>The code and short URI to display (<c>user_code_uri</c> start mode).</summary>
    public UserCodeUri? UserCodeUri => Response.UserCodeUri;

    /// <summary>When the interaction modes expire, when the AS said so.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>
    /// The finish method the client requested (<c>redirect</c> or <c>push</c>), or
    /// <see langword="null"/> when the client polls for the result.
    /// </summary>
    public string? FinishMethod { get; }

    /// <summary>The callback URI the client registered for the finish method.</summary>
    public string? FinishUri { get; }

    /// <summary>Whether the client receives a finish callback (as opposed to polling).</summary>
    public bool ExpectsCallback => FinishMethod is not null && Response.Finish is not null;

    private static Uri? AbsoluteOrNull(string? value) =>
        value is not null && Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null;
}

/// <summary>
/// The result of an interaction as handed back to the client: a received
/// finish callback (redirect query or push body) to verify, or a request to
/// poll the AS.
/// </summary>
public sealed class GnapInteractionOutcome
{
    private GnapInteractionOutcome(InteractionFinishCallback? callback, string? failure)
    {
        Callback = callback;
        Failure = failure;
    }

    /// <summary>Poll the continuation URI until the AS has a decision (RFC 9635 Section 5.2).</summary>
    public static GnapInteractionOutcome Poll { get; } = new(null, null);

    /// <summary>The verified-to-be finish callback, or <see langword="null"/> for <see cref="Poll"/>.</summary>
    public InteractionFinishCallback? Callback { get; }

    /// <summary>Why the received callback could not be read, if it could not.</summary>
    internal string? Failure { get; }

    /// <summary>Whether this outcome asks the client to poll.</summary>
    public bool IsPoll => Callback is null && Failure is null;

    /// <summary>
    /// The URI the end user's browser was redirected to at the end of the
    /// interaction (RFC 9635 Section 4.2.1), carrying <c>hash</c> and <c>interact_ref</c>.
    /// </summary>
    public static GnapInteractionOutcome FromRedirect(Uri redirectUri)
    {
        ArgumentNullException.ThrowIfNull(redirectUri);
        return InteractionFinishCallback.TryParseRedirectUri(redirectUri, out var callback)
            ? new GnapInteractionOutcome(callback, null)
            : new GnapInteractionOutcome(null, "The finish redirect lacks a 'hash' or 'interact_ref' parameter (or repeats one).");
    }

    /// <summary>The JSON body the AS POSTed to the client's push URI (RFC 9635 Section 4.2.2).</summary>
    public static GnapInteractionOutcome FromPush(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        InteractionFinishCallback? callback;
        try
        {
            callback = Core.Json.GnapJson.DeserializeFinishCallback(json);
        }
        catch (System.Text.Json.JsonException)
        {
            callback = null;
        }

        return callback is { Hash.Length: > 0, InteractRef.Length: > 0 }
            ? new GnapInteractionOutcome(callback, null)
            : new GnapInteractionOutcome(null, "The finish push body lacks 'hash' or 'interact_ref' or is not valid JSON.");
    }

    /// <summary>An already parsed finish callback.</summary>
    public static GnapInteractionOutcome FromCallback(InteractionFinishCallback callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        return string.IsNullOrEmpty(callback.Hash) || string.IsNullOrEmpty(callback.InteractRef)
            ? new GnapInteractionOutcome(null, "The finish callback lacks 'hash' or 'interact_ref'.")
            : new GnapInteractionOutcome(callback, null);
    }
}
