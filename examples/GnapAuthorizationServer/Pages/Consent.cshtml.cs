using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace GnapAuthorizationServer.Pages;

/// <summary>
/// The reference consent UI: shows who asks for what and lets the resource owner
/// approve or deny. The demo "login" is a user name field; a real AS authenticates
/// the RO here (e.g. with ASP.NET Core Identity) before showing the consent.
/// </summary>
public sealed class ConsentModel(IGnapInteractionService interactions, IResourceSetStore resourceSets) : PageModel
{
    /// <summary>
    /// Access references (RFC 9767 resource sets registered by resource servers) resolved
    /// to the rights they stand for, so the resource owner sees and approves concrete rights.
    /// </summary>
    public IReadOnlyDictionary<string, IList<AccessRight>> ResolvedReferences { get; private set; } =
        new Dictionary<string, IList<AccessRight>>();

    /// <summary>The interaction identifier from the AS redirect.</summary>
    [BindProperty(SupportsGet = true)]
    public string? Interaction { get; set; }

    /// <summary>The demo resource owner name.</summary>
    [BindProperty]
    public string? UserName { get; set; }

    /// <summary>The pending interaction shown on the page.</summary>
    public GnapInteractionContext? Pending { get; private set; }

    /// <summary>Shows the consent form, or an error for an unknown/foreign interaction.</summary>
    public async Task<IActionResult> OnGetAsync()
    {
        Pending = await interactions.GetInteractionAsync(HttpContext, Interaction ?? string.Empty);
        if (Pending is null)
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
        }
        else
        {
            ResolvedReferences = await ResolveReferencesAsync(Pending);
        }

        return Page();
    }

    private async Task<Dictionary<string, IList<AccessRight>>> ResolveReferencesAsync(GnapInteractionContext pending)
    {
        var resolved = new Dictionary<string, IList<AccessRight>>(StringComparer.Ordinal);
        foreach (var right in pending.AccessTokens.SelectMany(t => t.Access ?? []))
        {
            if (right.IsReference && !resolved.ContainsKey(right.Reference!)
                && await resourceSets.FindAsync(right.Reference!, HttpContext.RequestAborted) is { } set)
            {
                resolved[right.Reference!] = set.Access;
            }
        }

        return resolved;
    }

    /// <summary>Approves the request as the entered user.</summary>
    public async Task<IActionResult> OnPostApproveAsync()
    {
        if (string.IsNullOrWhiteSpace(UserName))
        {
            ModelState.AddModelError(nameof(UserName), "Please enter your user name.");
            return await OnGetAsync();
        }

        var pending = await interactions.GetInteractionAsync(HttpContext, Interaction ?? string.Empty);
        if (pending is null)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // Grant what was requested, with registered access references replaced by the
        // rights they stand for (the AS does not expand references on its own).
        var references = await ResolveReferencesAsync(pending);
        var access = pending.AccessTokens
            .Select(t => (IList<AccessRight>)(t.Access ?? [])
                .SelectMany(r => r.IsReference && references.TryGetValue(r.Reference!, out var rights) ? rights : [r])
                .ToList())
            .ToList();

        var completion = await interactions.ApproveAsync(HttpContext, Interaction ?? string.Empty, new GrantApproval
        {
            Access = access,
            ResourceOwner = UserName,
            Subject = new SubjectResponse
            {
                SubIds = [new SubjectIdentifier { Format = SubjectIdentifierFormats.Opaque, Id = UserName }],
            },
        });
        return Finish(completion);
    }

    /// <summary>Denies the request.</summary>
    public async Task<IActionResult> OnPostDenyAsync() =>
        Finish(await interactions.DenyAsync(HttpContext, Interaction ?? string.Empty));

    private IActionResult Finish(GnapInteractionCompletion completion)
    {
        if (!completion.Succeeded)
        {
            return StatusCode(StatusCodes.Status403Forbidden);
        }

        // Redirect finish: back to the client. Push finish or polling: the client
        // already has (or will fetch) the result; tell the user they are done.
        return completion.RedirectUri is { } redirect
            ? Redirect(redirect.AbsoluteUri)
            : RedirectToPage("Done");
    }
}
