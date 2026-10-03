using GnapAuthorizationServer;
using GnapAuthorizationServer.Storage;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.EntityFrameworkCore;

// A complete GNAP authorization server:
//  - the Gnap.AspNetCore endpoints under /gnap (grant endpoint: /gnap/tx),
//  - a Razor Pages consent UI at /consent (the reference IGnapInteractionService client),
//  - grants, tokens and client instances persisted with EF Core (SQLite),
//  - a demo policy: registered client instances are approved directly,
//    everybody else needs the resource owner's consent,
//  - resource servers registered from configuration for RFC 9767 introspection:
//    ResourceServers:0:Id = "demo-rs", ResourceServers:0:Jwk = "{ public JWK JSON }"
//    (see examples/docker-compose.yml).
var builder = WebApplication.CreateBuilder(args);

var resourceServers = new InMemoryResourceServerStore();
foreach (var rs in builder.Configuration.GetSection("ResourceServers").GetChildren())
{
    var jwk = System.Text.Json.JsonSerializer.Deserialize(rs["Jwk"] ?? "null", GnapJsonContext.Default.JsonWebKey)
        ?? throw new InvalidOperationException($"ResourceServers:{rs.Key}:Jwk is missing.");
    resourceServers.Add(new ResourceServerRegistration
    {
        Id = rs["Id"] ?? throw new InvalidOperationException($"ResourceServers:{rs.Key}:Id is missing."),
        Key = GnapKey.ForHttpSig(jwk.ToPublicKey()),
    });
}

builder.Services.AddRazorPages();
builder.Services.AddDbContext<GnapDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Gnap") ?? "Data Source=gnap-as.db"));

builder.Services
    .AddGnapAuthorizationServer(options =>
    {
        options.SubjectIdFormatsSupported = [SubjectIdentifierFormats.Opaque];
        options.AllowBearerTokens = true;
    })
    .AddGrantStore<EfGrantStore>()
    .AddTokenStore<EfTokenStore>()
    .AddClientKeyStore<EfClientKeyStore>()
    .AddResourceServerStore(resourceServers)
    .AddGrantPolicy<DemoGrantPolicy>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<GnapDbContext>().Database.EnsureCreated();
}

app.MapGnapAuthorizationServer();
app.MapRazorPages();
app.MapGet("/", () => Results.Text(
    "GNAP authorization server. Grant endpoint: /gnap/tx, discovery: /.well-known/gnap-as-rs, user code entry: /gnap/device"));

app.Run();

/// <summary>The entry point, public for <c>WebApplicationFactory</c> in tests.</summary>
public partial class Program;
