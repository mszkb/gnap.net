using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;

namespace Gnap.AspNetCore.AuthorizationServer.Policy;

/// <summary>
/// Decides what happens to a grant request (RFC 9635 Section 1.4): approve it
/// right away, deny it, or ask the RO through an interaction. The registered
/// default is <see cref="DenyAllGrantPolicy"/> (deny by default), so an AS only
/// grants what its own policy explicitly allows.
/// </summary>
public interface IGrantPolicy
{
    /// <summary>Evaluates a verified grant request (the client's key proof has already been checked).</summary>
    ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken = default);
}

/// <summary>Who is asking, as established by the AS from the request and its key proof.</summary>
public sealed class ClientIdentity
{
    /// <summary>The client instance's key, resolved to key material.</summary>
    public required GnapKey Key { get; init; }

    /// <summary>The RFC 7638 thumbprint of <see cref="Key"/>'s JWK — a stable identifier for the key.</summary>
    public required string KeyThumbprint { get; init; }

    /// <summary>The instance identifier when the client presented itself by reference (a registered client).</summary>
    public string? InstanceId { get; init; }

    /// <summary>The client software identifier (<c>class_id</c>).</summary>
    public string? ClassId { get; init; }

    /// <summary>Display information (self-asserted unless the client is registered).</summary>
    public ClientDisplay? Display { get; init; }

    /// <summary>Whether the client was identified through a pre-registered instance or key reference.</summary>
    public bool IsRegistered { get; init; }
}

/// <summary>The input of an <see cref="IGrantPolicy"/> decision.</summary>
public sealed class GrantPolicyContext
{
    /// <summary>The HTTP request carrying the grant request.</summary>
    public required HttpContext HttpContext { get; init; }

    /// <summary>The verified client identity.</summary>
    public required ClientIdentity Client { get; init; }

    /// <summary>The grant request (requested access tokens, subject information, user, interaction).</summary>
    public required GrantRequest Request { get; init; }

    /// <summary>Whether the client offered an interaction start mode this AS supports.</summary>
    public bool CanInteract { get; init; }
}

/// <summary>The kinds of <see cref="GrantDecision"/>.</summary>
public enum GrantDecisionKind
{
    /// <summary>Deny the request.</summary>
    Deny,

    /// <summary>Approve the request without interaction.</summary>
    Approve,

    /// <summary>Ask the RO through an interaction.</summary>
    RequireInteraction,
}

/// <summary>The outcome of an <see cref="IGrantPolicy"/>.</summary>
public sealed class GrantDecision
{
    private GrantDecision(GrantDecisionKind kind, GrantApproval? approval, GnapErrorCode error)
    {
        Kind = kind;
        Approval = approval;
        Error = error;
    }

    /// <summary>The kind of decision.</summary>
    public GrantDecisionKind Kind { get; }

    /// <summary>What is approved, for <see cref="GrantDecisionKind.Approve"/>.</summary>
    public GrantApproval? Approval { get; }

    /// <summary>The error code returned for <see cref="GrantDecisionKind.Deny"/>.</summary>
    public GnapErrorCode Error { get; }

    /// <summary>Approves the request (as requested unless <paramref name="approval"/> narrows it).</summary>
    public static GrantDecision Approve(GrantApproval? approval = null) =>
        new(GrantDecisionKind.Approve, approval ?? new GrantApproval(), default);

    /// <summary>Denies the request, by default with <c>request_denied</c>.</summary>
    public static GrantDecision Deny(GnapErrorCode? error = null) =>
        new(GrantDecisionKind.Deny, null, error ?? GnapErrorCode.RequestDenied);

    /// <summary>Requires the RO to approve the request through an interaction.</summary>
    public static GrantDecision RequireInteraction() => new(GrantDecisionKind.RequireInteraction, null, default);
}

/// <summary>
/// What an approval (by policy or by the RO's consent) grants. Unset members mean
/// "as requested" / "AS default".
/// </summary>
public sealed class GrantApproval
{
    /// <summary>
    /// The access granted per requested token, index-aligned with the request's
    /// <c>access_token</c> array. When set it must have one entry per requested
    /// token; this is how a policy or consent page grants less than requested.
    /// </summary>
    public IList<IList<AccessRight>>? Access { get; set; }

    /// <summary>The subject information released to the client (RFC 9635 Section 3.4), if requested.</summary>
    public SubjectResponse? Subject { get; set; }

    /// <summary>An identifier of the approving resource owner, recorded with the issued tokens.</summary>
    public string? ResourceOwner { get; set; }

    /// <summary>The lifetime of the issued access tokens; the AS default when unset.</summary>
    public TimeSpan? AccessTokenLifetime { get; set; }
}

/// <summary>The default policy: denies every request (deny by default).</summary>
public sealed class DenyAllGrantPolicy : IGrantPolicy
{
    /// <inheritdoc />
    public ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(GrantDecision.Deny());
}

/// <summary>An <see cref="IGrantPolicy"/> backed by a delegate.</summary>
public sealed class DelegateGrantPolicy : IGrantPolicy
{
    private readonly Func<GrantPolicyContext, CancellationToken, ValueTask<GrantDecision>> _evaluate;

    /// <summary>Creates the policy from an asynchronous delegate.</summary>
    public DelegateGrantPolicy(Func<GrantPolicyContext, CancellationToken, ValueTask<GrantDecision>> evaluate)
    {
        ArgumentNullException.ThrowIfNull(evaluate);
        _evaluate = evaluate;
    }

    /// <summary>Creates the policy from a synchronous delegate.</summary>
    public DelegateGrantPolicy(Func<GrantPolicyContext, GrantDecision> evaluate)
    {
        ArgumentNullException.ThrowIfNull(evaluate);
        _evaluate = (context, _) => ValueTask.FromResult(evaluate(context));
    }

    /// <inheritdoc />
    public ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken = default) =>
        _evaluate(context, cancellationToken);
}
