using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using Gnap.Client;
using Gnap.Client.Tokens;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http.Extensions;

// A web application acting as GNAP client with the redirect flow (RFC 9635 §4.1.1, §4.2.1):
//   GET /         start page
//   GET /connect  starts a grant (redirect start + redirect finish) and sends the browser to the AS
//   GET /callback verifies the finish hash, continues the grant and calls the resource server
//
// Configuration (environment variables use "__" for ":"):
//   Gnap:GrantEndpoint  default http://localhost:5100/gnap/tx (examples/GnapAuthorizationServer)
//   Gnap:Resource       default http://localhost:5200/photos  (examples/GnapResourceServer)
//   PublicUrl           this app's URL as the browser sees it, default http://localhost:5300
var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var grantEndpoint = new Uri(config["Gnap:GrantEndpoint"] ?? "http://localhost:5100/gnap/tx");
var resource = new Uri(config["Gnap:Resource"] ?? "http://localhost:5200/photos");
var publicUrl = new Uri(config["PublicUrl"] ?? "http://localhost:5300");

// One client instance key for the application (a real app loads it from a secret store).
var clientKey = GnapClientKey.FromJwk(JsonWebKey.FromECDsa(
    ECDsa.Create(ECCurve.NamedCurves.nistP256), includePrivateKey: true, keyId: "web-client"));

builder.Services.AddHttpClient();
builder.Services.AddSingleton(sp => new GnapClient(
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("gnap"),
    new GnapClientOptions
    {
        GrantEndpoint = grantEndpoint,
        ClientKey = clientKey,
        Display = new ClientDisplay { Name = "GNAP web client (example)", Uri = publicUrl.AbsoluteUri },
    }));

var app = builder.Build();

// Pending grants by a random per-browser state id (a real app uses its session store).
var pending = new ConcurrentDictionary<string, GnapPendingGrant>(StringComparer.Ordinal);
const string StateCookie = "gnap-demo-state";

app.MapGet("/", () => Html(
    "<h1>GNAP web client</h1>"
    + $"<p>This app wants to read your photos from <code>{WebUtility.HtmlEncode(resource.AbsoluteUri)}</code>.</p>"
    + "<p><a href=\"/connect\">Connect with the authorization server</a></p>"));

app.MapGet("/connect", async (HttpContext context, GnapClient client) =>
{
    var grant = await client.StartGrantAsync(new GrantRequest
    {
        AccessToken = [new AccessTokenRequest { Access = [new AccessRight { Type = "photo-api", Actions = ["read"] }] }],
        Interact = new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
            Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = new Uri(publicUrl, "/callback").AbsoluteUri },
        },
    }, cancellationToken: context.RequestAborted);

    var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    pending[state] = grant;
    context.Response.Cookies.Append(StateCookie, state, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax });
    return Results.Redirect(grant.Interaction!.RedirectUri!.AbsoluteUri);
});

app.MapGet("/callback", async (HttpContext context, GnapClient client, IHttpClientFactory httpClients) =>
{
    if (context.Request.Cookies[StateCookie] is not { } state || !pending.TryRemove(state, out var grant))
    {
        return Html("<h1>No pending grant</h1><p><a href=\"/\">Start again</a></p>", StatusCodes.Status400BadRequest);
    }

    context.Response.Cookies.Delete(StateCookie);
    GnapGrantResult result;
    try
    {
        // Verifies the finish hash, then continues the grant with interact_ref.
        result = await grant.CompleteWithRedirectAsync(new Uri(context.Request.GetEncodedUrl()), context.RequestAborted);
    }
    catch (GnapClientException e)
    {
        return Html($"<h1>Access was not granted</h1><p>{WebUtility.HtmlEncode(e.Message)}</p><p><a href=\"/\">Start again</a></p>",
            StatusCodes.Status403Forbidden);
    }

    // Call the RS with the key-bound token: Authorization: GNAP + httpsig signature.
    using var api = new HttpClient(new GnapAccessTokenHandler(client.CreateTokenSource(result.AccessToken!), new SocketsHttpHandler()));
    using var response = await api.GetAsync(resource, context.RequestAborted);
    var body = await response.Content.ReadAsStringAsync(context.RequestAborted);
    return Html(
        "<h1>Access granted</h1>"
        + $"<p>GET <code>{WebUtility.HtmlEncode(resource.AbsoluteUri)}</code> &rarr; {(int)response.StatusCode} {response.StatusCode}</p>"
        + $"<pre>{WebUtility.HtmlEncode(body)}</pre>"
        + "<p><a href=\"/\">Back</a></p>");
});

app.Run();

static IResult Html(string body, int statusCode = StatusCodes.Status200OK) => Results.Content(
    $"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>GNAP web client</title></head><body>{body}</body></html>",
    "text/html; charset=utf-8",
    statusCode: statusCode);
