using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace GnapAuthorizationServer.Pages;

/// <summary>
/// The reference consent UI: shows who asks for what and lets the resource owner
/// approve or deny. The demo "login" is a user name field; a real AS authenticates
/// the RO here (e.g. with ASP.NET Core Identity) before showing the consent.
/// </summary>
public sealed class ConsentModel(IGnapInteractionService interactions) : PageModel
{
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

        return Page();
    }

    /// <summary>Approves the request as the entered user.</summary>
    public async Task<IActionResult> OnPostApproveAsync()
    {
        if (string.IsNullOrWhiteSpace(UserName))
        {
            ModelState.AddModelError(nameof(UserName), "Please enter your user name.");
            return await OnGetAsync();
        }

        var completion = await interactions.ApproveAsync(HttpContext, Interaction ?? string.Empty, new GrantApproval
        {
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
