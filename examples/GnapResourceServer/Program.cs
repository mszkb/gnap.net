using System.Text.Json;
using Gnap.AspNetCore.ResourceServer;
using Gnap.Core.Json;
using Gnap.Core.Models;

// A GNAP-protected minimal API (resource server):
//  - accepts "Authorization: GNAP <token>" with an httpsig key proof by the token's key,
//  - validates tokens by RFC 9767 introspection at the AS (signed with the RS key, cached),
//  - registers its resource set at the AS and answers unauthenticated requests with
//    401 + WWW-Authenticate: GNAP as_uri=..., access=... (RS-first discovery).
//
// Configuration (environment variables use "__" for ":"):
//   Gnap:AuthorizationServer  AS origin, default http://localhost:5100
//   Gnap:ResourceServerId     identifier registered at the AS, default demo-rs
//   Gnap:SigningKey           the RS private JWK (JSON); its public part is registered at the AS
var builder = WebApplication.CreateBuilder(args);

var gnap = builder.Configuration.GetSection("Gnap");
var signingKey = JsonSerializer.Deserialize(
        gnap["SigningKey"] ?? throw new InvalidOperationException("Gnap:SigningKey (private JWK JSON) is not configured."),
        GnapJsonContext.Default.JsonWebKey)
    ?? throw new InvalidOperationException("Gnap:SigningKey is not a JWK.");

builder.Services.AddGnapResourceServer(options =>
{
    options.AuthorizationServer = new Uri(gnap["AuthorizationServer"] ?? "http://localhost:5100");
    options.ResourceServerId = gnap["ResourceServerId"] ?? "demo-rs";
    options.SigningKey = signingKey;
    options.ResourceSet = [new AccessRight { Type = "photo-api", Actions = ["read"] }];
});

var app = builder.Build();
app.UseGnapResourceServer();

app.MapGet("/", () => Results.Text(
    "GNAP resource server. GET /photos requires a GNAP token with access photo-api/read."));

app.MapGet("/photos", (HttpContext context) =>
{
    var token = context.GetGnapToken()!;
    return Results.Json(new PhotoList(
        Owner: token.Subject ?? "unknown",
        Photos: ["sunset.jpg", "mountains.jpg", "gnap-hackathon.png"]));
}).RequireGnapAccess("photo-api", "read");

app.Run();

/// <summary>The demo resource.</summary>
/// <param name="Owner">The resource owner the token was approved by.</param>
/// <param name="Photos">The photo names.</param>
internal sealed record PhotoList(string Owner, string[] Photos);

/// <summary>The entry point, public for <c>WebApplicationFactory</c> in tests.</summary>
public partial class Program;
