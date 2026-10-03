using Gnap.AspNetCore.AuthorizationServer.Policy;

namespace GnapAuthorizationServer;

/// <summary>
/// The demo policy: client instances the AS already knows (they present their
/// <c>instance_id</c>) are approved without interaction; any other client must
/// obtain the resource owner's consent. Requests that cannot interact are denied.
/// </summary>
internal sealed class DemoGrantPolicy : IGrantPolicy
{
    public ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken = default) =>
        ValueTask.FromResult(context.Client.IsRegistered
            ? GrantDecision.Approve(new GrantApproval { ResourceOwner = "registered:" + context.Client.InstanceId })
            : GrantDecision.RequireInteraction());
}
