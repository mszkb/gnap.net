using System.Net;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.AspNetCore.Tests;

public class IntrospectionTests
{
    private static readonly Uri Introspect = new("http://localhost/gnap/introspect");

    private static async Task<(AsHarness H, GnapClientKey Rs, GnapClient Client)> SetupAsync(bool allowBearer = false)
    {
        var h = await AsHarness.StartAsync(_ => GrantDecision.Approve(new GrantApproval { ResourceOwner = "alice" }), o => o.AllowBearerTokens = allowBearer);
        var rsJwk = AsHarness.NewEcKey("rs-key");
        var rs = GnapClientKey.FromJwk(rsJwk);
        h.ResourceServers.Add(new ResourceServerRegistration { Id = "photo-rs", Key = rs.PresentedKey });
        return (h, rs, h.CreateClient());
    }

    private static string Body(string token, string? proof = "httpsig", string rs = "photo-rs", string? access = null) =>
        $"{{\"access_token\":\"{token}\",\"resource_server\":\"{rs}\""
        + (proof is null ? string.Empty : $",\"proof\":\"{proof}\"")
        + (access is null ? string.Empty : $",\"access\":{access}")
        + "}";

    [Fact]
    public async Task ActiveKeyBoundToken_IsDescribed()
    {
        var (h, rs, client) = await SetupAsync();
        await using var _ = h;
        var token = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;

        var (status, body) = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: Body(token.Value));

        Assert.Equal(HttpStatusCode.OK, status);
        var json = JsonDocument.Parse(body).RootElement;
        Assert.True(json.GetProperty("active").GetBoolean());
        Assert.Equal("photo-api", json.GetProperty("access")[0].GetProperty("type").GetString());
        Assert.Equal(client.ClientKey.PresentedKey.Jwk!.X, json.GetProperty("key").GetProperty("jwk").GetProperty("x").GetString());
        Assert.Contains("httpsig", json.GetProperty("key").GetProperty("proof").GetRawText(), StringComparison.Ordinal);
        Assert.Equal(AsHarness.GrantEndpoint.AbsoluteUri, json.GetProperty("iss").GetString());
        Assert.Equal("alice", json.GetProperty("sub").GetString());
        Assert.Equal(h.Time.GetUtcNow().AddHours(1).ToUnixTimeSeconds(), json.GetProperty("exp").GetInt64());
        Assert.False(json.TryGetProperty("flags", out var _));
    }

    [Fact]
    public async Task InactiveTokens_RevealNothing()
    {
        var (h, rs, client) = await SetupAsync();
        await using var _ = h;
        var revoked = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;
        await client.RevokeTokenAsync(revoked);
        var active = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;

        var cases = new[]
        {
            Body("unknown-token"),
            Body(revoked.Value),
            Body(active.Value, proof: "bearer"), // presented without its key binding
            Body(active.Value, access: """[{"type":"photo-api","actions":["delete"]}]"""), // rights it does not carry
        };

        foreach (var request in cases)
        {
            var (status, body) = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: request);
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.Equal("""{"active":false}""", body);
        }

        h.Time.Advance(TimeSpan.FromHours(2));
        var (_, expired) = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: Body(active.Value));
        Assert.Equal("""{"active":false}""", expired);
    }

    [Fact]
    public async Task BearerToken_IsFlagged()
    {
        var (h, rs, client) = await SetupAsync(allowBearer: true);
        await using var _ = h;
        var request = AsHarness.PhotoRequest();
        request.AccessToken![0].Flags = [AccessTokenFlags.Bearer];
        var token = (await client.RequestAccessAsync(request)).AccessToken!;

        var (_, body) = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: Body(token.Value, proof: null));

        var json = JsonDocument.Parse(body).RootElement;
        Assert.True(json.GetProperty("active").GetBoolean());
        Assert.Equal("bearer", json.GetProperty("flags")[0].GetString());
        Assert.False(json.TryGetProperty("key", out var _));
    }

    [Fact]
    public async Task ResourceServerMustAuthenticate()
    {
        var (h, rs, client) = await SetupAsync();
        await using var _ = h;
        var token = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;
        var impostor = GnapClientKey.FromJwk(AsHarness.NewEcKey("rs-key"));

        var unsigned = await h.SendSignedAsync(HttpMethod.Post, Introspect, null, json: Body(token.Value));
        var wrongKey = await h.SendSignedAsync(HttpMethod.Post, Introspect, impostor, json: Body(token.Value));
        var unknownRs = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: Body(token.Value, rs: "other-rs"));
        var asClient = await h.SendSignedAsync(HttpMethod.Post, Introspect, client.ClientKey, json: Body(token.Value));

        Assert.All(new[] { unsigned, wrongKey, unknownRs, asClient }, r =>
        {
            Assert.Equal(HttpStatusCode.Unauthorized, r.Status);
            Assert.DoesNotContain("active", r.Body, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task MalformedRequest_IsInvalidRequest()
    {
        var (h, rs, _) = await SetupAsync();
        await using var _ = h;

        var (status, body) = await h.SendSignedAsync(HttpMethod.Post, Introspect, rs, json: """{"resource_server":"photo-rs"}""");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Contains("invalid_request", body, StringComparison.Ordinal);
    }
}

public class DependencyInjectionTests
{
    [Fact]
    public async Task StoresPolicyFormatAndPageAreReplaceable()
    {
        var grants = new CountingGrantStore();
        var tokens = new InMemoryTokenStore();
        var format = new PrefixTokenFormat();
        await using var h = await AsHarness.StartAsync(
            policy: null,
            configureServer: server =>
            {
                server.Services.AddSingleton(tokens);
                server.AddGrantStore(grants)
                    .AddTokenStore<SingletonTokenStore>()
                    .AddTokenFormat(format)
                    .AddInteractionPage<CustomPage>()
                    .AddGrantPolicy<ApproveReadPolicy>();
            });
        var client = h.CreateClient();

        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest("read"));

        Assert.StartsWith("custom-", result.AccessToken!.Value, StringComparison.Ordinal);
        Assert.True(grants.Creates > 0);
        Assert.Single(tokens.Tokens);
        var browser = h.CreateBrowser();
        using var page = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri("http://localhost/gnap/device")));
        Assert.Equal("custom user code page", await page.Content.ReadAsStringAsync());
        Assert.IsType<ApproveReadPolicy>(h.Services.CreateScope().ServiceProvider.GetRequiredService<IGrantPolicy>());
    }

    [Fact]
    public void ServicesRegisteredBeforehandWin()
    {
        var services = new ServiceCollection();
        var policy = new DelegateGrantPolicy(_ => GrantDecision.Approve());
        services.AddSingleton<IGrantPolicy>(policy);
        services.AddGnapAuthorizationServer();
        using var provider = services.BuildServiceProvider();

        Assert.Same(policy, provider.GetRequiredService<IGrantPolicy>());
        Assert.IsType<InMemoryGrantStore>(provider.GetRequiredService<IGrantStore>());
        Assert.IsType<OpaqueTokenFormat>(provider.GetRequiredService<ITokenFormat>());
        Assert.IsType<DefaultInteractionPage>(provider.GetRequiredService<IGnapInteractionPage>());
        Assert.NotNull(provider.CreateScope().ServiceProvider.GetRequiredService<IGnapInteractionService>());
    }

    private sealed class ApproveReadPolicy : IGrantPolicy
    {
        public ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(GrantDecision.Approve());
    }

    private sealed class PrefixTokenFormat : ITokenFormat
    {
        public ValueTask<string> CreateTokenAsync(AccessTokenDescriptor descriptor, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult("custom-" + descriptor.TokenId);
    }

    private sealed class CustomPage : IGnapInteractionPage
    {
        public Task StartInteractionAsync(HttpContext httpContext, string interactionId) => Task.CompletedTask;

        public Task ShowUserCodeFormAsync(HttpContext httpContext, bool invalidCode) => httpContext.Response.WriteAsync("custom user code page");

        public Task ShowErrorAsync(HttpContext httpContext, int statusCode) => Task.CompletedTask;
    }

    private sealed class CountingGrantStore : IGrantStore
    {
        private readonly InMemoryGrantStore _inner = new();

        public int Creates { get; private set; }

        public Task CreateAsync(GrantRecord grant, CancellationToken cancellationToken = default)
        {
            Creates++;
            return _inner.CreateAsync(grant, cancellationToken);
        }

        public Task<GrantRecord?> FindAsync(string grantId, CancellationToken cancellationToken = default) => _inner.FindAsync(grantId, cancellationToken);

        public Task<GrantRecord?> FindByInteractionIdAsync(string interactionId, CancellationToken cancellationToken = default) => _inner.FindByInteractionIdAsync(interactionId, cancellationToken);

        public Task<GrantRecord?> FindByUserCodeAsync(string userCode, CancellationToken cancellationToken = default) => _inner.FindByUserCodeAsync(userCode, cancellationToken);

        public Task<bool> TryUpdateAsync(GrantRecord grant, CancellationToken cancellationToken = default) => _inner.TryUpdateAsync(grant, cancellationToken);
    }

    private sealed class SingletonTokenStore(InMemoryTokenStore inner) : ITokenStore
    {
        public Task StoreAsync(TokenRecord token, CancellationToken cancellationToken = default) => inner.StoreAsync(token, cancellationToken);

        public Task<TokenRecord?> FindByValueHashAsync(string valueHash, CancellationToken cancellationToken = default) => inner.FindByValueHashAsync(valueHash, cancellationToken);

        public Task<TokenRecord?> FindByManageIdAsync(string manageId, CancellationToken cancellationToken = default) => inner.FindByManageIdAsync(manageId, cancellationToken);

        public Task<bool> RevokeAsync(string tokenId, CancellationToken cancellationToken = default) => inner.RevokeAsync(tokenId, cancellationToken);

        public Task RevokeByGrantAsync(string grantId, CancellationToken cancellationToken = default) => inner.RevokeByGrantAsync(grantId, cancellationToken);
    }
}
