using System.Text.Encodings.Web;
using Gnap.AspNetCore.AuthorizationServer.Endpoints;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer.Interaction;

/// <summary>
/// The user-facing side of the interaction endpoints: where the browser goes once
/// an interaction is bound to its session, the user code entry form, and error
/// pages. Replace it to integrate your own UI; the consent decision itself is made
/// through <see cref="IGnapInteractionService"/>.
/// </summary>
public interface IGnapInteractionPage
{
    /// <summary>
    /// Continues a session-bound interaction, typically by redirecting to the consent
    /// UI. The default redirects to <see cref="GnapAuthorizationServerOptions.ConsentPath"/>
    /// with the <c>interaction</c> query parameter.
    /// </summary>
    Task StartInteractionAsync(HttpContext httpContext, string interactionId);

    /// <summary>Renders the user code entry form (posting <c>user_code</c> back to the same URI).</summary>
    Task ShowUserCodeFormAsync(HttpContext httpContext, bool invalidCode);

    /// <summary>Renders an error for an unknown, expired or foreign-session interaction.</summary>
    Task ShowErrorAsync(HttpContext httpContext, int statusCode);
}

/// <summary>The built-in, dependency-free <see cref="IGnapInteractionPage"/>.</summary>
public sealed class DefaultInteractionPage(IOptions<GnapAuthorizationServerOptions> options) : IGnapInteractionPage
{
    /// <inheritdoc />
    public Task StartInteractionAsync(HttpContext httpContext, string interactionId)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var target = httpContext.Request.PathBase.Add(options.Value.ConsentPath).ToUriComponent()
            + "?interaction=" + Uri.EscapeDataString(interactionId);
        httpContext.Response.Redirect(target);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task ShowUserCodeFormAsync(HttpContext httpContext, bool invalidCode)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        var action = HtmlEncoder.Default.Encode(httpContext.Request.PathBase.Add(httpContext.Request.Path).ToUriComponent());
        var message = invalidCode ? "<p role=\"alert\">The code is invalid or has expired.</p>" : string.Empty;
        httpContext.Response.StatusCode = invalidCode ? StatusCodes.Status400BadRequest : StatusCodes.Status200OK;
        return WriteHtmlAsync(httpContext, "Enter code", $"""
            <h1>Connect a device</h1>
            {message}
            <form method="post" action="{action}">
              <label for="user_code">Code shown on your device</label>
              <input id="user_code" name="user_code" autocomplete="off" autofocus required>
              <button type="submit">Continue</button>
            </form>
            """);
    }

    /// <inheritdoc />
    public Task ShowErrorAsync(HttpContext httpContext, int statusCode)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        httpContext.Response.StatusCode = statusCode;
        return WriteHtmlAsync(httpContext, "Request not available", "<h1>This request is not available</h1><p>It is unknown, has expired, was already completed, or was opened in a different browser.</p>");
    }

    private static Task WriteHtmlAsync(HttpContext httpContext, string title, string body)
    {
        httpContext.Response.ContentType = "text/html; charset=utf-8";
        httpContext.Response.Headers.CacheControl = "no-store";
        return httpContext.Response.WriteAsync(
            $"<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body>{body}</body></html>",
            httpContext.RequestAborted);
    }
}

/// <summary>
/// The browser-facing interaction endpoints: <c>GET {BasePath}/interact/{id}</c>
/// (redirect start mode) and <c>GET|POST {BasePath}/device</c> (user code entry).
/// </summary>
internal sealed class InteractionEndpoint(GnapInteractionService interactions, IGnapInteractionPage page)
{
    public async Task StartAsync(HttpContext context)
    {
        var grant = await interactions.FindPendingAsync(context.Request.RouteValues["interactionId"] as string, context.RequestAborted).ConfigureAwait(false);
        await ContinueAsync(context, grant).ConfigureAwait(false);
    }

    public Task ShowUserCodeFormAsync(HttpContext context) => page.ShowUserCodeFormAsync(context, invalidCode: false);

    public async Task SubmitUserCodeAsync(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            await page.ShowUserCodeFormAsync(context, invalidCode: true).ConfigureAwait(false);
            return;
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var code = GrantEndpoint.NormalizeUserCode(form["user_code"].ToString());
        var grant = code.Length == 0 ? null : await interactions.FindByUserCodeAsync(code, context.RequestAborted).ConfigureAwait(false);
        if (grant is null)
        {
            await page.ShowUserCodeFormAsync(context, invalidCode: true).ConfigureAwait(false);
            return;
        }

        await ContinueAsync(context, grant).ConfigureAwait(false);
    }

    private async Task ContinueAsync(HttpContext context, GrantRecord? grant)
    {
        if (grant is null)
        {
            await page.ShowErrorAsync(context, StatusCodes.Status400BadRequest).ConfigureAwait(false);
            return;
        }

        if (!await interactions.BindSessionAsync(context, grant).ConfigureAwait(false))
        {
            await page.ShowErrorAsync(context, StatusCodes.Status403Forbidden).ConfigureAwait(false);
            return;
        }

        await page.StartInteractionAsync(context, grant.InteractionId!).ConfigureAwait(false);
    }
}
