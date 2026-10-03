using System.Net;
using System.Text.Json;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.AspNetCore.Tests;

/// <summary>Negative tests: every attack is rejected and leaves no trace in the grant state.</summary>
public class SecurityTests
{
    private static string GrantJson(GnapClientKey key, InteractRequest? interact = null)
    {
        var request = AsHarness.PhotoRequest();
        request.Client = new ClientInstance { Key = key.PresentedKey };
        request.Interact = interact;
        return GnapJson.Serialize(request);
    }

    private static GnapErrorCode ErrorCode(string body) =>
        GnapJson.DeserializeGrantResponse(body)!.Error!.Code;

    private static async Task<(GnapClient Client, GnapPendingGrant Pending, Uri Callback)> StartRedirectGrantAsync(AsHarness h)
    {
        var client = h.CreateClient();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.Redirect(AsHarness.Callback, (_, _) => throw new InvalidOperationException()));
        var callback = await h.CreateBrowser().FollowAsync(pending.Interaction!.RedirectUri!);
        return (client, pending, callback!);
    }

    [Fact]
    public async Task ReplayedGrantRequest_IsRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var key = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));
        using var original = RawRequests.Create(HttpMethod.Post, AsHarness.GrantEndpoint, null, GrantJson(key));
        await key.CreateProofer(h.Time).AddProofAsync(original);
        using var replay = await RawRequests.CloneAsync(original);

        var (firstStatus, _) = await RawRequests.SendAsync(h.Http, original);
        var (replayStatus, replayBody) = await RawRequests.SendAsync(h.Http, replay);

        Assert.Equal(HttpStatusCode.OK, firstStatus);
        Assert.Equal(HttpStatusCode.Unauthorized, replayStatus);
        Assert.Equal(GnapErrorCode.InvalidClient, ErrorCode(replayBody));
        Assert.Single(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task SignatureOutsideCreatedWindow_IsRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var key = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));

        var (stale, staleBody) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, key, json: GrantJson(key), clock: new FixedTimeProvider(h.Time.GetUtcNow().AddMinutes(-11)));
        var (future, _) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, key, json: GrantJson(key), clock: new FixedTimeProvider(h.Time.GetUtcNow().AddMinutes(10)));

        Assert.Equal(HttpStatusCode.Unauthorized, stale);
        Assert.Equal(HttpStatusCode.Unauthorized, future);
        Assert.Equal(GnapErrorCode.InvalidClient, ErrorCode(staleBody));
        Assert.Empty(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task UnsignedOrMissignedGrantRequest_IsRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var key = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));
        var attacker = AsHarness.NewEcKey("client-key-1");

        var (unsigned, _) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, null, json: GrantJson(key));

        // Signed with a different private key while presenting the victim's public key.
        var impostor = new GnapClientKey(attacker.ToSignatureAlgorithm(), key.PresentedKey, "client-key-1");
        var (forged, _) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, impostor, json: GrantJson(key));

        Assert.Equal(HttpStatusCode.Unauthorized, unsigned);
        Assert.Equal(HttpStatusCode.Unauthorized, forged);
        Assert.Empty(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task ForeignExpiredRotatedOrUnknownContinuation_IsRejectedIndistinguishably()
    {
        await using var h = await AsHarness.StartAsync();
        var victim = h.CreateClient();
        var attacker = h.CreateClient(AsHarness.NewEcKey("attacker"));
        var handler = GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask);
        var victimGrant = await victim.StartGrantAsync(AsHarness.PhotoRequest(), handler);
        var attackerGrant = await attacker.StartGrantAsync(AsHarness.PhotoRequest(), handler);
        var victimUri = new Uri(victimGrant.Continue!.Uri!);
        var oldVictimToken = victimGrant.Continue.AccessToken!.Value!;
        h.Time.Advance(TimeSpan.FromSeconds(5));

        // The attacker's own (valid) continuation token on the victim's grant.
        var foreign = await h.SendSignedAsync(HttpMethod.Post, victimUri, attacker.ClientKey, attackerGrant.Continue!.AccessToken!.Value);

        // A rotated-away continuation token of the victim, correctly signed by the victim.
        await victimGrant.ContinueOnceAsync(null);
        var rotated = await h.SendSignedAsync(HttpMethod.Post, victimUri, victim.ClientKey, oldVictimToken);

        // A continuation for a grant that does not exist.
        var unknown = await h.SendSignedAsync(HttpMethod.Post, new Uri("http://localhost/gnap/continue/does-not-exist"), victim.ClientKey, oldVictimToken);

        // The victim's current token after the grant expired.
        h.Time.Advance(TimeSpan.FromMinutes(11));
        var expired = await h.SendSignedAsync(HttpMethod.Post, victimUri, victim.ClientKey, victimGrant.Continue!.AccessToken!.Value);

        foreach (var (status, body) in new[] { foreign, rotated, unknown, expired })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, status);
            Assert.Equal(GnapErrorCode.InvalidContinuation, ErrorCode(body));
            Assert.Equal(foreign.Body, body); // no information leak: byte-identical answers
        }
    }

    [Fact]
    public async Task ContinuationSignedWithOtherKey_IsRejected()
    {
        await using var h = await AsHarness.StartAsync();
        var (client, pending, callback) = await StartRedirectGrantAsync(h);
        Assert.True(InteractionFinishCallback.TryParseRedirectUri(callback, out var finish));
        var otherKey = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() =>
            client.Protocol.ContinueGrantAsync(pending.Continue!, finish.InteractRef, otherKey));

        Assert.Equal(GnapErrorCode.InvalidClient, error.Code);

        // The grant is untouched: the genuine client still completes it.
        var result = await pending.CompleteWithRedirectAsync(callback);
        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task TamperedInteractRef_IsRejectedAndGrantUntouched()
    {
        await using var h = await AsHarness.StartAsync();
        var (client, pending, callback) = await StartRedirectGrantAsync(h);

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() =>
            client.Protocol.ContinueGrantAsync(pending.Continue!, "tampered-interact-ref", client.ClientKey));

        Assert.Equal(GnapErrorCode.InvalidInteraction, error.Code);
        Assert.Empty(h.TokenStore.Tokens);
        var result = await pending.CompleteWithRedirectAsync(callback);
        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task SecondContinuationWithUsedInteractRef_IsUnknownInteraction()
    {
        await using var h = await AsHarness.StartAsync();
        var (client, pending, callback) = await StartRedirectGrantAsync(h);
        Assert.True(InteractionFinishCallback.TryParseRedirectUri(callback, out var finish));
        var result = await pending.CompleteWithRedirectAsync(callback);

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() =>
            client.Protocol.ContinueGrantAsync(result.Continue!, finish.InteractRef, client.ClientKey));

        Assert.Equal(GnapErrorCode.UnknownInteraction, error.Code);
        Assert.Single(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task PollingBeforeWait_IsTooFast()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask));

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() =>
            client.Protocol.ContinueGrantAsync(pending.Continue!, null, client.ClientKey));

        Assert.Equal(GnapErrorCode.TooFast, error.Code);
    }

    [Fact]
    public async Task InteractionIsBoundToTheFirstBrowser()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        h.Consent = _ => throw new InvalidOperationException("must not be reached by the second browser");
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.Redirect(AsHarness.Callback, (_, _) => throw new InvalidOperationException()));
        var redirect = pending.Interaction!.RedirectUri!;

        // The first browser opens the interaction and is bound to it (session cookie).
        var victim = h.CreateBrowser();
        using (var first = await victim.SendAsync(new HttpRequestMessage(HttpMethod.Get, redirect)))
        {
            Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        }

        // A second browser (e.g. an attacker who obtained the link) is refused, also at the consent page.
        var attacker = h.CreateBrowser();
        var refused = await Assert.ThrowsAsync<HttpRequestException>(() => attacker.FollowAsync(redirect));
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        var interactionId = redirect.Segments[^1];
        var consent = await Assert.ThrowsAsync<HttpRequestException>(() => attacker.FollowAsync(new Uri($"http://localhost/consent?interaction={interactionId}")));
        Assert.Equal(HttpStatusCode.Forbidden, consent.StatusCode);
        Assert.Empty(h.ConsentShown);
    }

    [Fact]
    public async Task UserCodeIsSingleUse()
    {
        await using var h = await AsHarness.StartAsync();
        h.Consent = _ => null;
        var client = h.CreateClient();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask));
        var code = pending.Interaction!.UserCode!;

        await h.CreateBrowser().EnterUserCodeAsync(code);
        var reuse = await Assert.ThrowsAsync<HttpRequestException>(() => h.CreateBrowser().EnterUserCodeAsync(code));

        Assert.Equal(HttpStatusCode.BadRequest, reuse.StatusCode);
    }

    [Fact]
    public async Task ExpiredInteraction_CannotBeStarted()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.Redirect(AsHarness.Callback, (_, _) => throw new InvalidOperationException()));

        h.Time.Advance(TimeSpan.FromMinutes(10));
        var error = await Assert.ThrowsAsync<HttpRequestException>(() => h.CreateBrowser().FollowAsync(pending.Interaction!.RedirectUri!));

        Assert.Equal(HttpStatusCode.BadRequest, error.StatusCode);
    }

    [Fact]
    public async Task DenialIsReportedOnce()
    {
        await using var h = await AsHarness.StartAsync();
        h.Consent = _ => null;
        var (client, pending, callback) = await StartRedirectGrantAsync(h);
        Assert.True(InteractionFinishCallback.TryParseRedirectUri(callback, out var finish));

        var denied = await Assert.ThrowsAsync<GnapProtocolException>(() => pending.CompleteWithRedirectAsync(callback));
        var again = await Assert.ThrowsAsync<GnapProtocolException>(() =>
            client.Protocol.ContinueGrantAsync(pending.Continue!, finish.InteractRef, client.ClientKey));

        Assert.Equal(GnapErrorCode.UserDenied, denied.Code);
        Assert.Equal(GnapErrorCode.InvalidContinuation, again.Code);
    }

    [Theory]
    [InlineData("""{"access_token":{"access":["a"],"flags":["bearer"]}}""", "invalid_flag")]
    [InlineData("""{"access_token":{"access":["a"],"flags":["durable"]}}""", "invalid_flag")]
    [InlineData("""{"access_token":[{"access":["a"]},{"access":["b"]}]}""", "invalid_request")]
    [InlineData("""{"access_token":[{"access":["a"],"label":"x"},{"access":["b"],"label":"x"}]}""", "invalid_request")]
    [InlineData("""{"access_token":{"access":[]}}""", "invalid_request")]
    [InlineData("""{}""", "invalid_request")]
    [InlineData("""{"access_token":{"access":["a"]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://c.example/cb","nonce":"n","hash_method":"md5"}}}""", "invalid_request")]
    [InlineData("""{"access_token":{"access":["a"]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"not-a-uri","nonce":"n"}}}""", "invalid_request")]
    [InlineData("""{"access_token":{"access":["a"]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://c.example/cb"}}}""", "invalid_request")]
    public async Task InvalidGrantRequests_AreRejected(string requestWithoutClient, string expectedCode)
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var key = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));
        using var document = JsonDocument.Parse(requestWithoutClient);
        var members = document.RootElement.EnumerateObject().Select(p => $"\"{p.Name}\":{p.Value.GetRawText()}").ToList();
        members.Add($"\"client\":{{\"key\":{JsonSerializer.Serialize(key.PresentedKey, GnapJsonContext.Default.GnapKey)}}}");

        var (status, body) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, key, json: "{" + string.Join(",", members) + "}");

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(expectedCode, ErrorCode(body).Value);
        Assert.Empty(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task MalformedJsonAndPrivateKeyMaterial_AreRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var jwk = AsHarness.NewEcKey("client-key-1");
        var key = GnapClientKey.FromJwk(jwk);
        var leaky = new GnapClientKey(jwk.ToSignatureAlgorithm(), new GnapKey { Proof = key.PresentedKey.Proof, Jwk = jwk }, "client-key-1");

        var (malformedStatus, malformed) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, key, json: "{not json");
        var (leakyStatus, _) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, leaky, json: GrantJson(leaky));

        Assert.Equal(HttpStatusCode.BadRequest, malformedStatus);
        Assert.Equal(GnapErrorCode.InvalidRequest, ErrorCode(malformed));
        Assert.Equal(HttpStatusCode.Unauthorized, leakyStatus);
    }

    [Fact]
    public async Task ErrorDescriptionsAreGeneric()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var key = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));

        var (_, unsigned) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, null, json: GrantJson(key));
        var (_, stale) = await h.SendSignedAsync(HttpMethod.Post, AsHarness.GrantEndpoint, key, json: GrantJson(key), clock: new FixedTimeProvider(h.Time.GetUtcNow().AddHours(-1)));

        // Different failure causes, identical answers: the reason only goes to the log.
        Assert.Equal(unsigned, stale);
        Assert.DoesNotContain("signature", unsigned, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnknownInstanceAndKeyReferences_AreRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var jwk = AsHarness.NewEcKey("client-key-1");
        var byInstance = h.CreateClient(jwk, o => o.InstanceId = "unknown-instance");
        var byKeyRef = h.CreateClient(jwk, o => o.ClientKey = GnapClientKey.FromJwk(jwk).WithReference("unknown-key"));

        var e1 = await Assert.ThrowsAsync<GnapProtocolException>(() => byInstance.RequestAccessAsync(AsHarness.PhotoRequest()));
        var e2 = await Assert.ThrowsAsync<GnapProtocolException>(() => byKeyRef.RequestAccessAsync(AsHarness.PhotoRequest()));

        Assert.Equal(GnapErrorCode.InvalidClient, e1.Code);
        Assert.Equal(GnapErrorCode.InvalidClient, e2.Code);
    }

    [Fact]
    public async Task TokenManagementRequiresManagementTokenAndKey()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var client = h.CreateClient();
        var token = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;
        var manageUri = new Uri(token.Token.Manage!.Uri!);
        var otherKey = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1"));

        var (wrongTokenStatus, _) = await h.SendSignedAsync(HttpMethod.Delete, manageUri, client.ClientKey, accessToken: token.Value);
        var (wrongKeyStatus, _) = await h.SendSignedAsync(HttpMethod.Delete, manageUri, otherKey, accessToken: token.Token.Manage.AccessToken!.Value);

        Assert.Equal(HttpStatusCode.Unauthorized, wrongTokenStatus);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongKeyStatus);
        Assert.All(h.TokenStore.Tokens, t => Assert.False(t.Revoked));
    }

    [Fact]
    public async Task KeyRotationWithoutProofOfNewKey_IsRejected()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var client = h.CreateClient();
        var token = (await client.RequestAccessAsync(AsHarness.PhotoRequest())).AccessToken!;
        var newKey = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-2"));
        var body = $"{{\"key\":{JsonSerializer.Serialize(newKey.PresentedKey, GnapJsonContext.Default.GnapKey)}}}";

        // Signed only by the current key: possession of the new key is not proven.
        var (status, response) = await h.SendSignedAsync(HttpMethod.Post, new Uri(token.Token.Manage!.Uri!), client.ClientKey, token.Token.Manage.AccessToken!.Value, body);

        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal(GnapErrorCode.InvalidRotation, ErrorCode(response));
        Assert.All(h.TokenStore.Tokens, t => Assert.False(t.Revoked));
    }

    [Fact]
    public async Task ConcurrentContinuations_OnlyOneWins()
    {
        await using var h = await AsHarness.StartAsync();
        var (client, pending, callback) = await StartRedirectGrantAsync(h);
        Assert.True(InteractionFinishCallback.TryParseRedirectUri(callback, out var finish));

        var attempts = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            try
            {
                return (await client.Protocol.ContinueGrantAsync(pending.Continue!, finish.InteractRef, client.ClientKey)).AccessToken is { Count: > 0 };
            }
            catch (GnapProtocolException)
            {
                return false;
            }
        }));

        Assert.Single(attempts, issued => issued);
        Assert.Single(h.Services.GetRequiredService<ITokenStore>() is InMemoryTokenStore store ? store.Tokens.Where(t => !t.Revoked) : []);
    }
}
