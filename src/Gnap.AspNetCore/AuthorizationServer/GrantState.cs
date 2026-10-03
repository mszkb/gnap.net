namespace Gnap.AspNetCore.AuthorizationServer;

/// <summary>The lifecycle states of a grant (RFC 9635 Section 1.5).</summary>
public enum GrantState
{
    /// <summary>The grant request was received and is being evaluated by the AS.</summary>
    Processing,

    /// <summary>The grant waits for something outside the client instance, typically the RO's interaction.</summary>
    Pending,

    /// <summary>The grant was approved; tokens are issued on the next continuation.</summary>
    Approved,

    /// <summary>Tokens were issued; the grant can only be revoked from here.</summary>
    Finalized,

    /// <summary>The grant was denied or revoked. Terminal.</summary>
    Revoked,
}

/// <summary>
/// The legal transitions between <see cref="GrantState"/>s. Every state change of
/// a <see cref="Stores.GrantRecord"/> goes through <see cref="Stores.GrantRecord.TransitionTo"/>,
/// which enforces this table, so an illegal transition (e.g. issuing tokens for a
/// revoked grant) is impossible rather than merely unlikely.
/// </summary>
public static class GrantStateMachine
{
    /// <summary>Whether a grant may move from <paramref name="from"/> to <paramref name="to"/>.</summary>
    public static bool CanTransition(GrantState from, GrantState to) => (from, to) switch
    {
        (GrantState.Processing, GrantState.Pending) => true,
        (GrantState.Processing, GrantState.Approved) => true,
        (GrantState.Processing, GrantState.Revoked) => true,
        (GrantState.Pending, GrantState.Approved) => true,
        (GrantState.Pending, GrantState.Revoked) => true,
        (GrantState.Approved, GrantState.Finalized) => true,
        (GrantState.Approved, GrantState.Revoked) => true,
        (GrantState.Finalized, GrantState.Revoked) => true,
        _ => false,
    };
}
