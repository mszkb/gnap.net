using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Gnap.AspNetCore.Tests;

public class PolicyTests
{
    [Fact]
    public async Task DefaultPolicy_DeniesEverything()
    {
        // No policy registered: deny by default.
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddGnapAuthorizationServer();
        await using var app = builder.Build();
        app.MapGnapAuthorizationServer();
        await app.StartAsync();
        Assert.IsType<DenyAllGrantPolicy>(app.Services.GetRequiredService<IGrantPolicy>());

        using var http = app.GetTestClient();
        var client = new GnapClient(http, new GnapClientOptions
        {
            GrantEndpoint = AsHarness.GrantEndpoint,
            ClientKey = GnapClientKey.FromJwk(AsHarness.NewEcKey("k")),
        });

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(
            AsHarness.PhotoRequest(),
            GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask)));

        Assert.Equal(GnapErrorCode.RequestDenied, error.Code);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, error.StatusCode);
    }

    [Fact]
    public async Task PolicyDecisionsAreDeterministicAndSeeTheVerifiedClient()
    {
        var seen = new List<GrantPolicyContext>();
        await using var h = await AsHarness.StartAsync(context =>
        {
            seen.Add(context);
            var actions = context.Request.AccessToken!.SelectMany(t => t.Access!).SelectMany(a => a.Actions ?? []);
            return actions.Contains("delete") ? GrantDecision.Deny() : GrantDecision.Approve();
        });
        var jwk = AsHarness.NewEcKey("client-key-1");
        var client = h.CreateClient(jwk, o => o.ClassId = "photo-app");

        for (var i = 0; i < 3; i++)
        {
            Assert.NotNull((await client.RequestAccessAsync(AsHarness.PhotoRequest("read"))).AccessToken);
            var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(AsHarness.PhotoRequest("delete")));
            Assert.Equal(GnapErrorCode.RequestDenied, error.Code);
        }

        Assert.Equal(6, seen.Count);
        Assert.All(seen, c =>
        {
            Assert.Equal(jwk.ComputeThumbprint(), c.Client.KeyThumbprint);
            Assert.Equal("photo-app", c.Client.ClassId);
            Assert.False(c.Client.IsRegistered);
            Assert.False(c.CanInteract);
        });
    }

    [Fact]
    public async Task CustomDenialCode_IsReturned()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Deny(GnapErrorCode.UnknownUser));
        var client = h.CreateClient();

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(AsHarness.PhotoRequest()));

        Assert.Equal(GnapErrorCode.UnknownUser, error.Code);
    }

    [Fact]
    public async Task RequireInteractionWithoutInteractCapability_IsDenied()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.RequireInteraction());
        var client = h.CreateClient();

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(AsHarness.PhotoRequest()));

        Assert.Equal(GnapErrorCode.RequestDenied, error.Code);
        Assert.Empty(h.ConsentShown);
    }

    [Fact]
    public async Task PolicyCanNarrowAccessPerToken()
    {
        await using var h = await AsHarness.StartAsync(context => GrantDecision.Approve(new GrantApproval
        {
            Access = [.. context.Request.AccessToken!.Select(_ => (IList<AccessRight>)[AccessRight.ForReference("read-only")])],
            AccessTokenLifetime = TimeSpan.FromMinutes(5),
        }));
        var client = h.CreateClient();

        var token = (await client.RequestAccessAsync(AsHarness.PhotoRequest("read", "write"))).AccessToken!;

        Assert.Equal("read-only", Assert.Single(token.Access!).Reference);
        Assert.Equal(h.Time.GetUtcNow().AddMinutes(5), token.ExpiresAt);
    }
}

public class StateMachineTests
{
    public static TheoryData<GrantState, GrantState> AllTransitions()
    {
        var data = new TheoryData<GrantState, GrantState>();
        foreach (var from in Enum.GetValues<GrantState>())
        {
            foreach (var to in Enum.GetValues<GrantState>())
            {
                data.Add(from, to);
            }
        }

        return data;
    }

    private static readonly HashSet<(GrantState, GrantState)> Legal =
    [
        (GrantState.Processing, GrantState.Pending),
        (GrantState.Processing, GrantState.Approved),
        (GrantState.Processing, GrantState.Revoked),
        (GrantState.Pending, GrantState.Approved),
        (GrantState.Pending, GrantState.Revoked),
        (GrantState.Approved, GrantState.Finalized),
        (GrantState.Approved, GrantState.Revoked),
        (GrantState.Finalized, GrantState.Revoked),
    ];

    [Theory]
    [MemberData(nameof(AllTransitions))]
    public void OnlyLegalTransitionsSucceed(GrantState from, GrantState to)
    {
        var grant = NewGrant();
        grant.State = from;

        if (Legal.Contains((from, to)))
        {
            grant.TransitionTo(to);
            Assert.Equal(to, grant.State);
        }
        else
        {
            Assert.Throws<InvalidOperationException>(() => grant.TransitionTo(to));
            Assert.Equal(from, grant.State);
        }

        Assert.Equal(Legal.Contains((from, to)), GrantStateMachine.CanTransition(from, to));
    }

    [Fact]
    public void RevokedIsTerminal_AndTokensAreNeverIssuedTwice()
    {
        Assert.All(Enum.GetValues<GrantState>(), s => Assert.False(GrantStateMachine.CanTransition(GrantState.Revoked, s)));
        Assert.All(Enum.GetValues<GrantState>(), s => Assert.Equal(s == GrantState.Revoked, GrantStateMachine.CanTransition(GrantState.Finalized, s)));
        Assert.All(Enum.GetValues<GrantState>(), s => Assert.False(GrantStateMachine.CanTransition(s, GrantState.Processing)));
    }

    [Fact]
    public async Task InMemoryGrantStore_RejectsStaleVersions()
    {
        var store = new InMemoryGrantStore();
        var grant = NewGrant();
        grant.InteractionId = "ix";
        await store.CreateAsync(grant);

        var a = (await store.FindAsync(grant.Id))!;
        var b = (await store.FindAsync(grant.Id))!;
        a.State = GrantState.Pending;
        b.State = GrantState.Revoked;

        Assert.True(await store.TryUpdateAsync(a));
        Assert.False(await store.TryUpdateAsync(b));
        Assert.Equal(GrantState.Pending, (await store.FindByInteractionIdAsync("ix"))!.State);
        Assert.Equal(1, a.Version);
    }

    private static GrantRecord NewGrant() => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        Request = new GrantRequest(),
        ClientKey = GnapKey.ForHttpSig(AsHarness.NewEcKey("k")),
        GrantEndpointUri = AsHarness.GrantEndpoint.AbsoluteUri,
    };
}
