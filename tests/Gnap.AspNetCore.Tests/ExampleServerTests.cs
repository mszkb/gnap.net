using System.Net;
using System.Text.RegularExpressions;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.AspNetCore.Tests;

/// <summary>
/// The example AS (<c>examples/GnapAuthorizationServer</c>: Razor Pages consent UI,
/// EF Core/SQLite stores) through <see cref="WebApplicationFactory{TEntryPoint}"/>,
/// driven by the Phase 2 client and a simulated browser submitting the real
/// consent form (with antiforgery token).
/// </summary>
public sealed partial class ExampleServerTests : IDisposable
{
    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"gnap-as-test-{Guid.NewGuid():N}.db");
    private readonly VirtualTimeProvider _time = new();
    private readonly WebApplicationFactory<Program> _factory;

    public ExampleServerTests()
    {
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ConnectionStrings:Gnap", $"Data Source={_databasePath}");
            builder.ConfigureServices(services =>
                services.Configure<GnapAuthorizationServerOptions>(options => options.TimeProvider = _time));
        });
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();

    private GnapClient CreateClient(Gnap.Core.Keys.JsonWebKey jwk, string? instanceId = null) =>
        new(new HttpClient(_factory.Server.CreateHandler()), new GnapClientOptions
        {
            GrantEndpoint = AsHarness.GrantEndpoint,
            ClientKey = GnapClientKey.FromJwk(jwk),
            InstanceId = instanceId,
            Display = new ClientDisplay { Name = "Photo Printer" },
            TimeProvider = _time,
        });

    /// <summary>Opens the interaction, then submits the Razor consent form with the given handler.</summary>
    private async Task<HttpResponseMessage> ConsentAsync(Browser browser, Uri start, string handler, string? userName = "alice")
    {
        using var redirect = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Get, start));
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        var consentUri = new Uri(start, redirect.Headers.Location!);
        Assert.Equal("/consent", consentUri.AbsolutePath);

        using var page = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Get, consentUri));
        var html = await page.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("Photo Printer wants access", html, StringComparison.Ordinal);

        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value,
            ["Interaction"] = System.Web.HttpUtility.ParseQueryString(consentUri.Query)["interaction"]!,
        };
        if (userName is not null)
        {
            form["UserName"] = userName;
        }

        return await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, new Uri(consentUri, $"?handler={handler}"))
        {
            Content = new FormUrlEncodedContent(form),
        });
    }

    [Fact]
    public async Task RedirectFlow_WithRazorConsent_ThenRegisteredInstanceIsApprovedDirectly()
    {
        var jwk = AsHarness.NewEcKey("printer-key");
        var client = CreateClient(jwk);
        var request = AsHarness.PhotoRequest("read");
        request.Subject = new SubjectRequest { SubIdFormats = [SubjectIdentifierFormats.Opaque] };
        var pending = await client.StartGrantAsync(request, GnapInteractionHandler.Redirect(AsHarness.Callback, (_, _) => throw new InvalidOperationException()));

        using var approved = await ConsentAsync(_factory.CreateBrowser(), pending.Interaction!.RedirectUri!, "Approve");
        Assert.Equal(HttpStatusCode.Redirect, approved.StatusCode);
        var result = await pending.CompleteWithRedirectAsync(approved.Headers.Location!);

        Assert.NotNull(result.AccessToken);
        Assert.Equal("alice", result.Subject!.SubIds![0].Id);
        Assert.NotNull(result.InstanceId);

        // The instance id was persisted (EF Core); the demo policy approves registered instances directly.
        var registered = CreateClient(jwk, result.InstanceId);
        var direct = await registered.RequestAccessAsync(AsHarness.PhotoRequest("read"));
        Assert.NotNull(direct.AccessToken);

        // Token management against the EF Core token store.
        var rotated = await registered.RotateTokenAsync(direct.AccessToken!);
        await registered.RevokeTokenAsync(rotated);
        var reuse = await Assert.ThrowsAsync<GnapProtocolException>(() => registered.RotateTokenAsync(rotated));
        Assert.Equal(GnapErrorCode.InvalidRotation, reuse.Code);
    }

    [Fact]
    public async Task UserCodeFlow_WithRazorDenial_ReportsUserDenied()
    {
        var client = CreateClient(AsHarness.NewEcKey("tv-key"));
        var browser = _factory.CreateBrowser();

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(
            AsHarness.PhotoRequest("read"),
            GnapInteractionHandler.UserCode(async (interaction, _) =>
            {
                using var entered = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, new Uri(interaction.UserCodeUri!.Uri!))
                {
                    Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("user_code", interaction.UserCode!)]),
                });
                Assert.Equal(HttpStatusCode.Redirect, entered.StatusCode);
                var consentUri = new Uri(new Uri(interaction.UserCodeUri.Uri!), entered.Headers.Location!);
                var interactionId = System.Web.HttpUtility.ParseQueryString(consentUri.Query)["interaction"]!;
                using var denied = await ConsentAsync(browser, new Uri($"http://localhost/gnap/interact/{interactionId}"), "Deny", userName: null);
                Assert.Equal("/Done", denied.Headers.Location!.OriginalString);
            })));

        Assert.Equal(GnapErrorCode.UserDenied, error.Code);
    }

    [Fact]
    public async Task ConsentPage_RefusesForeignBrowser()
    {
        var client = CreateClient(AsHarness.NewEcKey("k"));
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.Redirect(AsHarness.Callback, (_, _) => throw new InvalidOperationException()));
        using var bound = await _factory.CreateBrowser().SendAsync(new HttpRequestMessage(HttpMethod.Get, pending.Interaction!.RedirectUri!));
        var consentUri = new Uri(pending.Interaction.RedirectUri!, bound.Headers.Location!);

        using var foreign = await _factory.CreateBrowser().SendAsync(new HttpRequestMessage(HttpMethod.Get, consentUri));

        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        Assert.Contains("not available", await foreign.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Discovery_IsServed()
    {
        var client = CreateClient(AsHarness.NewEcKey("k"));

        var metadata = await client.DiscoverAsync();

        Assert.Equal(AsHarness.GrantEndpoint.AbsoluteUri, metadata.GrantRequestEndpoint);
        Assert.Equal([SubjectIdentifierFormats.Opaque], metadata.SubIdFormatsSupported);
    }

    public void Dispose()
    {
        _factory.Dispose();
        SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(_databasePath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Best effort; the file lives in the temp directory.
        }
    }
}

internal static class FactoryExtensions
{
    public static Browser CreateBrowser(this WebApplicationFactory<Program> factory) => new(factory.Server);
}
