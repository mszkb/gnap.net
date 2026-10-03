using System.Text;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Gnap.AspNetCore.ResourceServer;
using Gnap.Client;
using Gnap.Client.Tokens;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Gnap.AspNetCore.Tests.Infrastructure;

/// <summary>How the RS under test validates tokens.</summary>
public enum TokenValidation
{
    /// <summary>A separate RS app introspecting at the AS (opaque tokens).</summary>
    Introspection,

    /// <summary>The RS co-hosted with the AS, reading its token store (opaque tokens).</summary>
    LocalStore,

    /// <summary>A separate RS app verifying JWT tokens locally with the AS's public key.</summary>
    Jwt,
}

/// <summary>
/// The four GNAP roles in one process: the real AS (<see cref="AsHarness"/>), a protected
/// RS built with <c>AddGnapResourceServer</c> (on its own <see cref="TestServer"/>, or
/// co-hosted in the AS app for <see cref="TokenValidation.LocalStore"/>), the Phase 2
/// client, and the RO simulated on the consent page. All share one virtual clock.
/// </summary>
internal sealed class RsHarness : IAsyncDisposable
{
    public const string ResourceServerId = "photo-rs";
    public static readonly Uri Photos = new("http://localhost/photos");
    public static readonly Uri WhoAmI = new("http://localhost/whoami");
    public static readonly AccessRight PhotoRead = new() { Type = "photo-api", Actions = ["read"], Locations = ["https://rs.example/photos"] };

    private readonly WebApplication? _rsApp;

    private RsHarness(AsHarness h, WebApplication? rsApp, TestServer server, CountingHandler backchannel, JsonWebKey rsKey)
    {
        As = h;
        _rsApp = rsApp;
        Server = server;
        Backchannel = backchannel;
        RsKey = rsKey;
        Http = new HttpClient(server.CreateHandler()) { BaseAddress = server.BaseAddress };
    }

    public AsHarness As { get; }

    public TestServer Server { get; }

    public HttpClient Http { get; }

    /// <summary>The RS's calls to the AS (discovery, registration, introspection).</summary>
    public CountingHandler Backchannel { get; }

    public JsonWebKey RsKey { get; }

    public IServiceProvider Services => _rsApp?.Services ?? As.Services;

    public GnapIntrospectionCache Cache => Services.GetRequiredService<GnapIntrospectionCache>();

    public int Introspections => Backchannel.Count("/gnap/introspect");

    public static async Task<RsHarness> StartAsync(
        TokenValidation mode = TokenValidation.Introspection,
        Action<GnapResourceServerOptions>? configure = null,
        Action<GnapAuthorizationServerOptions>? configureAs = null,
        Func<GrantPolicyContext, GrantDecision>? policy = null)
    {
        var rsKey = AsHarness.NewEcKey("rs-key");
        AsHarness? h = null;
        var backchannel = new CountingHandler(() => h!.Server.CreateHandler());
        JwtTokenFormat? jwt = mode == TokenValidation.Jwt ? new JwtTokenFormat(AsHarness.NewEcKey("as-jwt-key")) : null;

        void ConfigureOptions(GnapResourceServerOptions o)
        {
            o.TimeProvider = h!.Time;
            o.AuthorizationServer = new Uri("http://localhost");
            o.ResourceServerId = ResourceServerId;
            o.SigningKey = rsKey;
            o.ResourceSet = [PhotoRead];
            configure?.Invoke(o);
        }

        if (mode == TokenValidation.LocalStore)
        {
            h = await AsHarness.StartAsync(
                policy ?? ApproveExpandingReferences,
                configureAs,
                configureBuilder: b =>
                {
                    b.Services.AddGnapResourceServer(ConfigureOptions).UseLocalTokenStore();
                    b.Services.AddHttpClient(GnapResourceServerDefaults.BackchannelHttpClientName)
                        .ConfigurePrimaryHttpMessageHandler(() => backchannel);
                },
                configureApp: app =>
                {
                    app.UseGnapResourceServer();
                    MapResources(app);
                });
            h.ResourceServers.Add(new ResourceServerRegistration { Id = ResourceServerId, Key = GnapKey.ForHttpSig(rsKey) });
            return new RsHarness(h, null, h.Server, backchannel, rsKey);
        }

        h = await AsHarness.StartAsync(
            policy ?? ApproveExpandingReferences,
            configureAs,
            configureServer: jwt is null ? null : s => s.AddTokenFormat(jwt));
        h.ResourceServers.Add(new ResourceServerRegistration { Id = ResourceServerId, Key = GnapKey.ForHttpSig(rsKey) });

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var rs = builder.Services.AddGnapResourceServer(ConfigureOptions);
        if (jwt is not null)
        {
            rs.UseJwtTokens(jwt.PublicKey, AsHarness.GrantEndpoint.AbsoluteUri);
        }

        builder.Services.AddHttpClient(GnapResourceServerDefaults.BackchannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => backchannel);
        var app = builder.Build();
        app.UseGnapResourceServer();
        MapResources(app);
        await app.StartAsync();
        return new RsHarness(h, app, app.GetTestServer(), backchannel, rsKey);
    }

    /// <summary>Approves every grant, replacing registered access references by the rights they stand for.</summary>
    public static GrantDecision ApproveExpandingReferences(GrantPolicyContext context)
    {
        var sets = context.HttpContext.RequestServices.GetRequiredService<IResourceSetStore>();
        var access = new List<IList<AccessRight>>();
        foreach (var token in context.Request.AccessToken ?? [])
        {
            var rights = new List<AccessRight>();
            foreach (var right in token.Access ?? [])
            {
                var set = right.IsReference ? sets.FindAsync(right.Reference!).GetAwaiter().GetResult() : null;
                rights.AddRange(set?.Access ?? [right]);
            }

            access.Add(rights);
        }

        return GrantDecision.Approve(new GrantApproval { ResourceOwner = "alice", Access = access });
    }

    private static void MapResources(WebApplication app)
    {
        app.MapGet("/photos", (HttpContext c) => $"photos of {c.GetGnapToken()!.Subject}")
            .RequireGnapAccess("photo-api", "read");
        app.MapPost("/photos", async (HttpContext c) =>
        {
            using var reader = new StreamReader(c.Request.Body, Encoding.UTF8);
            return $"stored {await reader.ReadToEndAsync()}";
        }).RequireGnapAccess("photo-api", "write");
        app.MapDelete("/photos", () => "deleted").RequireGnapAccess("photo-api", "delete");
        app.MapGet("/whoami", (HttpContext c) =>
        {
            var token = c.GetGnapToken()!;
            return $"{c.User.Identity!.Name}|{token.InstanceId}|{token.IsBearer}|{c.User.FindAll(GnapClaimTypes.Access).Count()}";
        }).RequireGnapToken();
    }

    /// <summary>Obtains a token for <paramref name="rights"/> (default: photo read) for a new client.</summary>
    public async Task<(GnapClient Client, GnapAccessToken Token)> GetTokenAsync(bool bearer = false, params AccessRight[] rights)
    {
        var client = As.CreateClient();
        var request = new GrantRequest
        {
            AccessToken = [new AccessTokenRequest { Access = rights.Length > 0 ? rights : [PhotoRead], Flags = bearer ? [AccessTokenFlags.Bearer] : null }],
        };
        var token = (await client.RequestAccessAsync(request)).AccessToken!;
        return (client, token);
    }

    /// <summary>Calls the RS through the client's token handler (signs, presents, rotates on 401).</summary>
    public HttpClient CreateApiClient(GnapClient client, GnapAccessToken token) =>
        new(new GnapAccessTokenHandler(client.CreateTokenSource(token), Server.CreateHandler()));

    /// <summary>Sends a hand-crafted request: token presented, optionally signed by <paramref name="signer"/>, then tampered with.</summary>
    public async Task<HttpResponseMessage> SendAsync(
        HttpMethod method,
        Uri uri,
        string? token,
        GnapClientKey? signer,
        string? body = null,
        Action<HttpRequestMessage>? tamper = null,
        TimeProvider? clock = null)
    {
        using var request = RawRequests.Create(method, uri, token, body);
        if (signer is not null)
        {
            await signer.CreateProofer(clock ?? As.Time).AddProofAsync(request);
        }

        tamper?.Invoke(request);
        return await Http.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        if (_rsApp is not null)
        {
            await _rsApp.DisposeAsync();
        }

        await As.DisposeAsync();
    }
}

/// <summary>Forwards to a lazily created handler and counts requests per path.</summary>
internal sealed class CountingHandler(Func<HttpMessageHandler> createInner) : DelegatingHandler
{
    private readonly List<string> _paths = [];
    private bool _initialized;

    public int Count(string path)
    {
        lock (_paths)
        {
            return _paths.Count(p => p == path);
        }
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        lock (_paths)
        {
            if (!_initialized)
            {
                InnerHandler = createInner();
                _initialized = true;
            }

            _paths.Add(request.RequestUri!.AbsolutePath);
        }

        return base.SendAsync(request, cancellationToken);
    }
}
