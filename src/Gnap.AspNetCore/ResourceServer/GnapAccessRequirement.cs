using System.Security.Claims;
using System.Text.Json;
using Gnap.Core.Json;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>
/// An authorization requirement met when the request's GNAP access token carries a
/// matching right of access (RFC 9635 Section 8): either the access reference
/// <see cref="TypeOrReference"/> itself, or an object-form right of that <c>type</c>
/// listing all <see cref="Actions"/> (and, when given, all <see cref="Locations"/>).
/// </summary>
public sealed class GnapAccessRequirement : IAuthorizationRequirement
{
    private readonly Func<AccessRight, bool>? _predicate;

    /// <summary>Requires an access reference, or a right of the given type with the given actions.</summary>
    public GnapAccessRequirement(string typeOrReference, IReadOnlyList<string>? actions = null, IReadOnlyList<string>? locations = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(typeOrReference);
        TypeOrReference = typeOrReference;
        Actions = actions ?? [];
        Locations = locations ?? [];
    }

    /// <summary>Requires a right of access satisfying <paramref name="predicate"/>.</summary>
    public GnapAccessRequirement(Func<AccessRight, bool> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        _predicate = predicate;
        Actions = [];
        Locations = [];
    }

    /// <summary>The required access reference or <c>type</c>; <see langword="null"/> for a predicate requirement.</summary>
    public string? TypeOrReference { get; }

    /// <summary>The actions an object-form right must list.</summary>
    public IReadOnlyList<string> Actions { get; }

    /// <summary>The locations an object-form right must list.</summary>
    public IReadOnlyList<string> Locations { get; }

    /// <summary>Whether a single right of access satisfies the requirement.</summary>
    public bool IsSatisfiedBy(AccessRight right)
    {
        ArgumentNullException.ThrowIfNull(right);
        if (_predicate is not null)
        {
            return _predicate(right);
        }

        if (right.IsReference)
        {
            return right.Reference == TypeOrReference;
        }

        return right.Type == TypeOrReference
            && Actions.All(a => right.Actions?.Contains(a) is true)
            && Locations.All(l => right.Locations?.Contains(l) is true);
    }
}

/// <summary>Evaluates <see cref="GnapAccessRequirement"/> against the token of the request.</summary>
public sealed class GnapAccessAuthorizationHandler : AuthorizationHandler<GnapAccessRequirement>
{
    /// <inheritdoc />
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, GnapAccessRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requirement);
        var access = (context.Resource as HttpContext)?.Features.Get<IGnapTokenFeature>()?.Token.Access
            ?? ReadClaims(context.User);
        if (access.Any(requirement.IsSatisfiedBy))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }

    private static List<AccessRight> ReadClaims(ClaimsPrincipal user)
    {
        var rights = new List<AccessRight>();
        foreach (var identity in user.Identities.Where(i => i.IsAuthenticated && i.AuthenticationType == GnapResourceServerDefaults.AuthenticationScheme))
        {
            foreach (var claim in identity.FindAll(GnapClaimTypes.Access))
            {
                try
                {
                    if (JsonSerializer.Deserialize(claim.Value, GnapJsonContext.Default.AccessRight) is { } right)
                    {
                        rights.Add(right);
                    }
                }
                catch (JsonException)
                {
                    // Not a right of access; ignore.
                }
            }
        }

        return rights;
    }
}
