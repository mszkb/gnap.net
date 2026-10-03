using GnapAuthorizationServer;
using GnapAuthorizationServer.Storage;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.Core.Models;
using Microsoft.EntityFrameworkCore;

// A complete GNAP authorization server:
//  - the Gnap.AspNetCore endpoints under /gnap (grant endpoint: /gnap/tx),
//  - a Razor Pages consent UI at /consent (the reference IGnapInteractionService client),
//  - grants, tokens and client instances persisted with EF Core (SQLite),
//  - a demo policy: registered client instances are approved directly,
//    everybody else needs the resource owner's consent.
var builder = WebApplication.CreateBuilder(args);

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
