using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.AspNetCore.AuthorizationServer.Stores;

/// <summary>
/// The server-side state of one grant. Secrets (continuation token, interaction
/// reference, session binding) are kept only as SHA-256 hashes, so a leaked store
/// does not leak usable credentials. Stores persist the record as a whole and use
/// <see cref="Version"/> for optimistic concurrency (see <see cref="IGrantStore.TryUpdateAsync"/>).
/// </summary>
public sealed class GrantRecord
{
    /// <summary>The unguessable grant identifier; also the last path segment of the continuation URI.</summary>
    public required string Id { get; set; }

    /// <summary>The current lifecycle state. Change it only through <see cref="TransitionTo"/>.</summary>
    public GrantState State { get; set; } = GrantState.Processing;

    /// <summary>The optimistic concurrency version, incremented by the store on each successful update.</summary>
    public long Version { get; set; }

    /// <summary>When the grant request was received.</summary>
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>The grant request as received. Treat it as immutable.</summary>
    public required GrantRequest Request { get; set; }

    /// <summary>The client instance's key, resolved to key material (never a reference).</summary>
    public required GnapKey ClientKey { get; set; }

    /// <summary>The instance identifier, when the client presented itself by reference or one was issued.</summary>
    public string? InstanceId { get; set; }

    /// <summary>The client software identifier (<c>class_id</c>).</summary>
    public string? ClientClassId { get; set; }

    /// <summary>The display information of the client (from its registration when registered).</summary>
    public ClientDisplay? ClientDisplay { get; set; }

    /// <summary>Whether the client was identified through a pre-registered instance or key reference.</summary>
    public bool ClientIsRegistered { get; set; }

    /// <summary>The grant endpoint URI the client sent its request to (enters the finish hash).</summary>
    public required string GrantEndpointUri { get; set; }

    /// <summary>The SHA-256 hash of the current continuation access token.</summary>
    public string? ContinuationTokenHash { get; set; }

    /// <summary>When the current continuation access token stops being accepted.</summary>
    public DateTimeOffset? ContinuationExpiresAt { get; set; }

    /// <summary>The earliest time the next continuation call is accepted (<c>wait</c>).</summary>
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>The identifier in the interaction redirect URI.</summary>
    public string? InteractionId { get; set; }

    /// <summary>The normalized user code, while it can still be entered.</summary>
    public string? UserCode { get; set; }

    /// <summary>When the interaction modes expire.</summary>
    public DateTimeOffset? InteractionExpiresAt { get; set; }

    /// <summary>The SHA-256 hash of the session secret that binds the interaction to one browser.</summary>
    public string? InteractionSessionHash { get; set; }

    /// <summary>The AS nonce returned in <c>interact.finish</c>.</summary>
    public string? AsNonce { get; set; }

    /// <summary>The SHA-256 hash of the interaction reference handed to the client, until it is used.</summary>
    public string? InteractRefHash { get; set; }

    /// <summary>The SHA-256 hash of an interaction reference that was already used (one-time use).</summary>
    public string? ConsumedInteractRefHash { get; set; }

    /// <summary>The approval (from the policy or the RO's consent) awaiting token issuance.</summary>
    public GrantApproval? Approval { get; set; }

    /// <summary>The error code reported on the next continuation of a denied grant, e.g. <c>user_denied</c>.</summary>
    public string? DenialCode { get; set; }

    /// <summary>Whether the denial was already reported to the client.</summary>
    public bool DenialReported { get; set; }

    /// <summary>The finish parameters the client requested, if any.</summary>
    public InteractFinish? Finish => Request.Interact?.Finish;

    /// <summary>
    /// Moves the grant to <paramref name="next"/>, enforcing <see cref="GrantStateMachine"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">The transition is not allowed.</exception>
    public void TransitionTo(GrantState next)
    {
        if (!GrantStateMachine.CanTransition(State, next))
        {
            throw new InvalidOperationException($"Illegal grant state transition {State} -> {next}.");
        }

        State = next;
    }

    /// <summary>Creates a shallow copy; nested protocol objects are shared and must not be mutated.</summary>
    public GrantRecord Clone()
    {
        return (GrantRecord)MemberwiseClone();
    }
}
