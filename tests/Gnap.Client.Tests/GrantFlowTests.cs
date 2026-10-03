using Gnap.Client.Interaction;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Client.Tests;

public class GrantFlowTests
{
    private static readonly Uri Callback = new("https://client.example/callback?session=42");

    [Fact]
    public async Task RedirectFlow_GrantInteractionContinuationToken()
    {
        using var h = ClientHarness.Create();
        GnapInteraction? seen = null;
        var handler = GnapInteractionHandler.Redirect(Callback, (interaction, _) =>
        {
            seen = interaction;
            // The "browser": the RO approves at the AS, which redirects back with hash + interact_ref.
            return ValueTask.FromResult(h.As.ApproveAndRedirect());
        });

        var result = await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.NotNull(seen);
        Assert.StartsWith($"{FakeAuthorizationServer.AsBase}/interact/", seen!.RedirectUri!.AbsoluteUri, StringComparison.Ordinal);
        Assert.True(seen.ExpectsCallback);
        Assert.Equal(FinishMethods.Redirect, seen.FinishMethod);

        var token = Assert.Single(result.AccessTokens);
        Assert.NotNull(h.As.FindToken(token.Value));
        Assert.Same(h.Key, token.BoundKey);
        Assert.False(token.IsBearer);
        Assert.Equal(h.Time.GetUtcNow().AddSeconds(3600), token.ExpiresAt);
        Assert.StartsWith("instance-", result.InstanceId, StringComparison.Ordinal);

        // Grant request + interact_ref continuation, both signed and verified.
        h.AssertAllRequestsVerified(atLeast: 2);
        Assert.Equal(["/tx", $"/continue/{result.InstanceId!["instance-".Length..]}"], h.As.Requests.Select(r => r.Path));

        // The client sent its key by value, with a generated finish nonce.
        var sent = h.As.LastGrantRequest!;
        Assert.NotNull(sent.Client!.Key!.Jwk);
        Assert.Null(sent.Client.Key.Jwk!.D);
        Assert.Equal("Test Client", sent.Client.Display!.Name);
        Assert.False(string.IsNullOrEmpty(sent.Interact!.Finish!.Nonce));
        Assert.Equal(Callback.AbsoluteUri, sent.Interact.Finish.Uri);
    }

    [Fact]
    public async Task RedirectFlow_StepwiseForWebApps()
    {
        using var h = ClientHarness.Create();
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
            Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = Callback.AbsoluteUri },
        }));

        Assert.False(pending.IsCompleted);
        Assert.NotNull(pending.Interaction?.RedirectUri);
        Assert.NotNull(pending.ClientNonce);

        var result = await pending.CompleteWithRedirectAsync(h.As.ApproveAndRedirect());

        Assert.NotNull(result.AccessToken);
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public async Task PushFinish_VerifiesHashAndContinues()
    {
        using var h = ClientHarness.Create();
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
            Finish = new InteractFinish { Method = FinishMethods.Push, Uri = "https://client.example/push" },
        }));

        var pushBody = Gnap.Core.Json.GnapJson.Serialize(h.As.Approve());
        var result = await pending.CompleteWithPushAsync(pushBody);

        Assert.NotNull(result.AccessToken);
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-512")]
    public async Task RedirectFlow_HonoursHashMethod(string hashMethod)
    {
        using var h = ClientHarness.Create(o => o.FinishHashMethod = hashMethod);
        var handler = GnapInteractionHandler.Redirect(Callback, (_, _) => ValueTask.FromResult(h.As.ApproveAndRedirect()));

        var result = await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.NotNull(result.AccessToken);
        Assert.Equal(hashMethod, h.As.LastGrantRequest!.Interact!.Finish!.HashMethod);
    }

    [Fact]
    public async Task UserCodeFlow_PollsRespectingWaitAndAdoptsRotatedContinuationTokens()
    {
        using var h = ClientHarness.Create();
        h.As.ContinueWait = 7;
        h.As.PendingPolls = 2;
        GnapInteraction? shown = null;
        var handler = GnapInteractionHandler.UserCode((interaction, _) =>
        {
            shown = interaction;
            h.As.Approve(); // the user types the code on another device
            return ValueTask.CompletedTask;
        });

        var result = await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.Equal("A1BC-3DFF", shown!.UserCode);
        Assert.Equal("A1BC-3DFF", shown.UserCodeUri!.Code);
        Assert.False(shown.ExpectsCallback);
        Assert.Null(h.As.LastGrantRequest!.Interact!.Finish);
        Assert.NotNull(result.AccessToken);

        // Three polls (two pending, one final), each after the 7 s wait; the AS
        // rotates the continuation token every time and enforces wait (too_fast).
        Assert.Equal(3, h.As.Requests.Count(r => r.Path.StartsWith("/continue/", StringComparison.Ordinal)));
        Assert.Equal([TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(7), TimeSpan.FromSeconds(7)], h.Time.Delays);
        h.AssertAllRequestsVerified(atLeast: 4);
    }

    [Fact]
    public async Task Polling_UsesFiveSecondDefaultWait()
    {
        using var h = ClientHarness.Create();
        h.As.ContinueWait = null;
        var handler = GnapInteractionHandler.UserCode((_, _) =>
        {
            h.As.Approve();
            return ValueTask.CompletedTask;
        });

        await h.Client.RequestAccessAsync(ClientHarness.PhotoRequest(), handler);

        Assert.Equal([TimeSpan.FromSeconds(5)], h.Time.Delays);
    }

    [Fact]
    public async Task NoInteraction_TokenIssuedImmediately()
    {
        using var h = ClientHarness.Create();

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        var token = Assert.Single(result.AccessTokens);
        Assert.Equal("photo-api", token.Access![0].Reference);
        Assert.Single(h.As.Requests);
        h.AssertAllRequestsVerified();
    }

    [Fact]
    public async Task MultipleLabelledTokens_AndBearerFlag()
    {
        using var h = ClientHarness.Create();
        var request = new GrantRequest
        {
            AccessToken =
            [
                new AccessTokenRequest { Label = "read", Access = [AccessRight.ForReference("read")] },
                new AccessTokenRequest { Label = "public", Access = [AccessRight.ForReference("public")], Flags = [AccessTokenFlags.Bearer] },
            ],
        };

        var result = await h.Client.RequestAccessAsync(request);

        Assert.Equal(2, result.AccessTokens.Count);
        Assert.Same(h.Key, result.GetToken("read").BoundKey);
        Assert.True(result.GetToken("public").IsBearer);
        Assert.Null(result.GetToken("public").BoundKey);
        Assert.Throws<KeyNotFoundException>(() => result.GetToken("nope"));
    }

    [Fact]
    public async Task ClientByInstanceReference_StillSignsWithKey()
    {
        using var h = ClientHarness.Create(o => o.InstanceId = "client-541-ab");
        h.As.RegisteredInstances["client-541-ab"] = h.Jwk.ToPublicKey();

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.NotNull(result.AccessToken);
        Assert.Equal("client-541-ab", h.As.LastGrantRequest!.Client!.Reference);
        h.AssertAllRequestsVerified();
    }

    [Fact]
    public async Task KeyByReference_StillSignsWithKey()
    {
        using var h = ClientHarness.Create();
        h.As.KeyReferences["key-ref-7"] = h.Jwk.ToPublicKey();
        h.Client.UseClientKey(h.Key.WithReference("key-ref-7"));

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.NotNull(result.AccessToken);
        Assert.Equal("key-ref-7", h.As.LastGrantRequest!.Client!.Key!.Reference);
        h.AssertAllRequestsVerified();
    }

    [Fact]
    public async Task SubjectRequest_IsForwarded()
    {
        using var h = ClientHarness.Create();
        var request = ClientHarness.PhotoRequest();
        request.Subject = new SubjectRequest { SubIdFormats = ["opaque"] };

        await h.Client.RequestAccessAsync(request);

        Assert.Equal(["opaque"], h.As.LastGrantRequest!.Subject!.SubIdFormats);
    }

    [Fact]
    public async Task InteractionRequired_WithoutHandler_Throws()
    {
        using var h = ClientHarness.Create();
        var request = ClientHarness.PhotoRequest(new InteractRequest { Start = [new StartMode(StartModes.Redirect)] });

        var e = await Assert.ThrowsAsync<GnapClientException>(() => h.Client.RequestAccessAsync(request));
        Assert.Contains("interaction handler", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CancelGrant_DeletesAtContinuationUri()
    {
        using var h = ClientHarness.Create();
        var pending = await h.Client.StartGrantAsync(ClientHarness.PhotoRequest(new InteractRequest
        {
            Start = [new StartMode(StartModes.Redirect)],
        }));

        await pending.CancelAsync();

        Assert.Contains(h.As.Requests, r => r.Method == HttpMethod.Delete && r.Path.StartsWith("/continue/", StringComparison.Ordinal));
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public void ClientKey_RequiresPrivateKey()
    {
        var publicOnly = ClientHarness.NewEcKey("k").ToPublicKey();
        Assert.Throws<Gnap.Core.GnapException>(() => GnapClientKey.FromJwk(publicOnly));
    }

    [Fact]
    public async Task ObjectFormProof_PinsDigestAlgorithm()
    {
        var jwk = ClientHarness.NewEcKey("pinned");
        using var h = ClientHarness.Create(o => o.ClientKey = GnapClientKey.FromJwk(jwk, Gnap.HttpMessageSignatures.ContentDigestAlgorithm.Sha512));

        var result = await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);

        Assert.NotNull(result.AccessToken);
        Assert.Equal("ecdsa-p256-sha256", h.As.LastGrantRequest!.Client!.Key!.Proof!.HttpSigAlgorithm);
        h.AssertAllRequestsVerified();
    }
}
