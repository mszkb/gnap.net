using System.Net;
using System.Security.Cryptography;
using System.Text;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.Client;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gnap.AspNetCore.Tests.Infrastructure;

/// <summary>
/// The real AS (Gnap.AspNetCore) on an in-process <see cref="TestServer"/>, on
/// virtual time shared with the clients it creates. A minimal consent endpoint at
/// <c>/consent</c> simulates the RO through <see cref="IGnapInteractionService"/>,
/// and a <see cref="PushReceiver"/> captures <c>push</c> finish messages.
/// </summary>
internal sealed class AsHarness : IAsyncDisposable
{
    public static readonly Uri GrantEndpoint = new("http://localhost/gnap/tx");
    public static readonly Uri Callback = new("https://client.example/callback?state=42");
    public static readonly Uri PushUri = new("https://client.example/push");

    private readonly WebApplication _app;

    private AsHarness(WebApplication app, VirtualTimeProvider time, InMemoryClientKeyStore clientKeys, InMemoryResourceServerStore resourceServers, PushReceiver push)
    {
        _app = app;
        Time = time;
        ClientKeys = clientKeys;
        ResourceServers = resourceServers;
        Push = push;
        Server = app.GetTestServer();
        Http = new HttpClient(Server.CreateHandler()) { BaseAddress = Server.BaseAddress };
    }

    public VirtualTimeProvider Time { get; }

    public TestServer Server { get; }

    public HttpClient Http { get; }

    public IServiceProvider Services => _app.Services;

    public InMemoryClientKeyStore ClientKeys { get; }

    public InMemoryResourceServerStore ResourceServers { get; }

    public PushReceiver Push { get; }

    /// <summary>The simulated RO's decision on the consent page; <see langword="null"/> denies.</summary>
    public Func<GnapInteractionContext, GrantApproval?> Consent { get; set; } =
        _ => new GrantApproval { ResourceOwner = "alice" };

    /// <summary>The interactions the consent page displayed.</summary>
    public List<GnapInteractionContext> ConsentShown { get; } = [];

    public static async Task<AsHarness> StartAsync(
        Func<GrantPolicyContext, GrantDecision>? policy = null,
        Action<GnapAuthorizationServerOptions>? configure = null,
        Action<GnapAuthorizationServerBuilder>? configureServer = null)
    {
        var time = new VirtualTimeProvider();
        AsHarness? harness = null;
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        var clientKeys = new InMemoryClientKeyStore();
        var resourceServers = new InMemoryResourceServerStore();
        var push = new PushReceiver();
        var server = builder.Services.AddGnapAuthorizationServer(options =>
        {
            options.TimeProvider = time;
            configure?.Invoke(options);
        });
        server.AddGrantPolicy(policy ?? (_ => GrantDecision.RequireInteraction()))
            .AddClientKeyStore(clientKeys)
            .AddResourceServerStore(resourceServers);
        configureServer?.Invoke(server);
        builder.Services.AddHttpClient(GnapAuthorizationServerOptions.PushHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => push);

        var app = builder.Build();
        app.MapGnapAuthorizationServer();
        app.MapGet("/consent", async context =>
        {
            var interactions = context.RequestServices.GetRequiredService<IGnapInteractionService>();
            var id = context.Request.Query["interaction"].ToString();
            var interaction = await interactions.GetInteractionAsync(context, id);
            if (interaction is null)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            harness!.ConsentShown.Add(interaction);
            var approval = harness.Consent(interaction);
            var completion = approval is null
                ? await interactions.DenyAsync(context, id)
                : await interactions.ApproveAsync(context, id, approval);
            if (!completion.Succeeded)
            {
                context.Response.StatusCode = StatusCodes.Status409Conflict;
            }
            else if (completion.RedirectUri is { } redirect)
            {
                context.Response.Redirect(redirect.AbsoluteUri);
            }
            else
            {
                await context.Response.WriteAsync("done");
            }
        });

        await app.StartAsync();
        harness = new AsHarness(app, time, clientKeys, resourceServers, push);
        return harness;
    }

    public GnapClient CreateClient(JsonWebKey? jwk = null, Action<GnapClientOptions>? configure = null)
    {
        var options = new GnapClientOptions
        {
            GrantEndpoint = GrantEndpoint,
            ClientKey = GnapClientKey.FromJwk(jwk ?? NewEcKey("client-key-1")),
            Display = new ClientDisplay { Name = "Test Client" },
            TimeProvider = Time,
        };
        configure?.Invoke(options);
        return new GnapClient(Http, options);
    }

    public Browser CreateBrowser() => new(Server);

    public static JsonWebKey NewEcKey(string kid)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: kid);
    }

    public static GrantRequest PhotoRequest(params string[] actions) => new()
    {
        AccessToken =
        [
            new AccessTokenRequest
            {
                Access = [new AccessRight { Type = "photo-api", Actions = actions.Length > 0 ? actions : ["read"], Locations = ["https://rs.example/photos"] }],
            },
        ],
    };

    public InMemoryTokenStore TokenStore => (InMemoryTokenStore)Services.GetRequiredService<ITokenStore>();

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await _app.DisposeAsync();
    }
}

/// <summary>Captures <c>push</c> finish messages the AS sends to the client.</summary>
internal sealed class PushReceiver : HttpMessageHandler
{
    public List<(Uri Uri, string Body)> Received { get; } = [];

    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        lock (Received)
        {
            Received.Add((request.RequestUri!, body));
        }

        return new HttpResponseMessage(Status);
    }
}

/// <summary>
/// A minimal browser against the test server: keeps cookies, follows redirects
/// within the AS, and stops at the first redirect leaving it (the client callback).
/// </summary>
internal sealed class Browser(TestServer server)
{
    private readonly HttpClient _http = new(server.CreateHandler());

    public CookieContainer Cookies { get; } = new();

    public List<HttpStatusCode> Statuses { get; } = [];

    /// <summary>Opens <paramref name="uri"/> and follows AS-internal redirects.</summary>
    /// <returns>The external redirect target (client callback), or <see langword="null"/> if the browser stayed on the AS.</returns>
    public async Task<Uri?> FollowAsync(Uri uri) => await FollowAsync(new HttpRequestMessage(HttpMethod.Get, uri));

    /// <summary>Submits a user code at the device page and follows the resulting redirects.</summary>
    public Task<Uri?> EnterUserCodeAsync(string code) =>
        FollowAsync(new HttpRequestMessage(HttpMethod.Post, new Uri("http://localhost/gnap/device"))
        {
            Content = new FormUrlEncodedContent([new KeyValuePair<string, string>("user_code", code)]),
        });

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
    {
        var cookie = Cookies.GetCookieHeader(request.RequestUri!);
        if (cookie.Length > 0)
        {
            request.Headers.Add("Cookie", cookie);
        }

        var response = await _http.SendAsync(request);
        if (response.Headers.TryGetValues("Set-Cookie", out var values))
        {
            foreach (var value in values)
            {
                Cookies.SetCookies(request.RequestUri!, value);
            }
        }

        Statuses.Add(response.StatusCode);
        return response;
    }

    private async Task<Uri?> FollowAsync(HttpRequestMessage request)
    {
        for (var hops = 0; hops < 10; hops++)
        {
            var current = request.RequestUri!;
            using var response = await SendAsync(request);
            if ((int)response.StatusCode is >= 300 and < 400 && response.Headers.Location is { } location)
            {
                var target = location.IsAbsoluteUri ? location : new Uri(current, location);
                if (target.Host != current.Host)
                {
                    return target;
                }

                request = new HttpRequestMessage(HttpMethod.Get, target);
                continue;
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Browser got HTTP {(int)response.StatusCode} at {current}: {Encoding.UTF8.GetString(await response.Content.ReadAsByteArrayAsync())}", null, response.StatusCode);
            }

            return null;
        }

        throw new InvalidOperationException("Too many redirects.");
    }
}
