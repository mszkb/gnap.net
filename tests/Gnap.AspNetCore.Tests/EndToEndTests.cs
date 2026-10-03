using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.AspNetCore.Tests;

/// <summary>
/// The Phase 2 client (<see cref="GnapClient"/>, unmodified) against the real AS on
/// a test server: every flow end to end, with the RO simulated on the consent page.
/// </summary>
public class EndToEndTests
{
    [Fact]
    public async Task RedirectFlow_ConsentFinishHashContinuationToken()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var browser = h.CreateBrowser();
        Uri? callback = null;

        var result = await client.RequestAccessAsync(
            AsHarness.PhotoRequest("read", "write"),
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (interaction, _) =>
            {
                Assert.StartsWith("http://localhost/gnap/interact/", interaction.RedirectUri!.AbsoluteUri, StringComparison.Ordinal);
                callback = await browser.FollowAsync(interaction.RedirectUri);
                return callback!;
            }));

        // The browser came back to the client's callback with hash + interact_ref
        // (keeping the client's own query), and the client verified the hash.
        Assert.StartsWith(AsHarness.Callback.AbsoluteUri + "&hash=", callback!.AbsoluteUri, StringComparison.Ordinal);
        var token = Assert.Single(result.AccessTokens);
        Assert.False(token.IsBearer);
        Assert.Same(client.ClientKey, token.BoundKey);
        Assert.Equal(["read", "write"], token.Access![0].Actions);
        Assert.Equal(h.Time.GetUtcNow().AddHours(1), token.ExpiresAt);
        Assert.True(token.CanBeManaged);
        Assert.NotNull(result.InstanceId);

        var shown = Assert.Single(h.ConsentShown);
        Assert.Equal("Test Client", shown.Client.Display!.Name);
        Assert.False(shown.Client.IsRegistered);

        var stored = Assert.Single(h.TokenStore.Tokens);
        Assert.Equal("alice", stored.ResourceOwner);
        Assert.NotEqual(token.Value, stored.ValueHash);
    }

    [Theory]
    [InlineData("sha-256")]
    [InlineData("sha-512")]
    [InlineData("sha3-512")]
    public async Task RedirectFlow_HonoursHashMethod(string hashMethod)
    {
        if (!Gnap.Core.InteractionFinishHash.IsSupported(hashMethod))
        {
            return; // SHA-3 is not available on every platform.
        }

        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient(configure: o => o.FinishHashMethod = hashMethod);
        var browser = h.CreateBrowser();

        var result = await client.RequestAccessAsync(
            AsHarness.PhotoRequest(),
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (i, _) => (await browser.FollowAsync(i.RedirectUri!))!));

        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task PushFinish_AsPostsHashAndInteractRefToClient()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var browser = h.CreateBrowser();
        var handler = GnapInteractionHandler.Create(
            new InteractRequest
            {
                Start = [new StartMode(StartModes.Redirect)],
                Finish = new InteractFinish { Method = FinishMethods.Push, Uri = AsHarness.PushUri.AbsoluteUri },
            },
            async (interaction, _) =>
            {
                Assert.Null(await browser.FollowAsync(interaction.RedirectUri!)); // browser stays on the AS ("done")
                var (uri, body) = Assert.Single(h.Push.Received);
                Assert.Equal(AsHarness.PushUri, uri);
                return GnapInteractionOutcome.FromPush(body);
            });

        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest(), handler);

        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task UserCodeFlow_DeviceEntryThenPolling()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var browser = h.CreateBrowser();
        GnapInteraction? shown = null;

        var result = await client.RequestAccessAsync(
            AsHarness.PhotoRequest(),
            GnapInteractionHandler.UserCode(async (interaction, _) =>
            {
                shown = interaction;
                // The user types the code (lower case, without the dash) on another device.
                Assert.Null(await browser.EnterUserCodeAsync(interaction.UserCode!.Replace("-", "", StringComparison.Ordinal).ToLowerInvariant()));
            }));

        Assert.Matches("^[A-Z]{4}-[A-Z]{4}$", shown!.UserCode);
        Assert.Equal(shown.UserCode, shown.UserCodeUri!.Code);
        Assert.Equal("http://localhost/gnap/device", shown.UserCodeUri.Uri);
        Assert.NotNull(result.AccessToken);
        Assert.Contains(TimeSpan.FromSeconds(5), h.Time.Delays); // the client respected 'wait'
    }

    [Fact]
    public async Task UserCodeFlow_PendingPollsRotateContinuationToken()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var browser = h.CreateBrowser();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask));

        var first = pending.Continue!.AccessToken!.Value;
        var stillPending = await pending.ContinueOnceAsync(null);
        Assert.NotNull(stillPending.Continue);
        Assert.NotEqual(first, stillPending.Continue!.AccessToken!.Value);

        await browser.EnterUserCodeAsync(pending.Interaction!.UserCode!);
        var result = await pending.PollAsync();

        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task PolicyApproval_IssuesTokensWithoutInteraction()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve(new GrantApproval { ResourceOwner = "service" }));
        var client = h.CreateClient();

        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());

        Assert.NotNull(result.AccessToken);
        Assert.Empty(h.ConsentShown);
        Assert.NotNull(result.Continue); // kept for revoking the grant
    }

    [Fact]
    public async Task MultipleLabeledTokens_AndBearer()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve(), o => o.AllowBearerTokens = true);
        var client = h.CreateClient();

        var result = await client.RequestAccessAsync(new GrantRequest
        {
            AccessToken =
            [
                new AccessTokenRequest { Label = "photos", Access = [AccessRight.ForReference("photo-read")] },
                new AccessTokenRequest { Label = "public", Access = [AccessRight.ForReference("feed")], Flags = [AccessTokenFlags.Bearer] },
            ],
        });

        Assert.Equal(2, result.AccessTokens.Count);
        var photos = result.GetToken("photos");
        var feed = result.GetToken("public");
        Assert.False(photos.IsBearer);
        Assert.NotNull(photos.BoundKey);
        Assert.True(feed.IsBearer);
        Assert.Null(feed.BoundKey);
        Assert.Equal("feed", feed.Access![0].Reference);
    }

    [Fact]
    public async Task ConsentNarrowsAccessAndReleasesSubject()
    {
        await using var h = await AsHarness.StartAsync();
        h.Consent = interaction => new GrantApproval
        {
            Access = [[new AccessRight { Type = "photo-api", Actions = ["read"] }]],
            Subject = new SubjectResponse { SubIds = [new SubjectIdentifier { Format = SubjectIdentifierFormats.Opaque, Id = "alice-123" }] },
        };
        var client = h.CreateClient();
        var browser = h.CreateBrowser();
        var request = AsHarness.PhotoRequest("read", "write", "delete");
        request.Subject = new SubjectRequest { SubIdFormats = [SubjectIdentifierFormats.Opaque] };

        var result = await client.RequestAccessAsync(
            request,
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (i, _) => (await browser.FollowAsync(i.RedirectUri!))!));

        Assert.Equal(["read"], result.AccessToken!.Access![0].Actions);
        Assert.Equal("alice-123", result.Subject!.SubIds![0].Id);
        Assert.Equal(SubjectIdentifierFormats.Opaque, Assert.Single(h.ConsentShown).Subject!.SubIdFormats![0]);
    }

    [Fact]
    public async Task UserDenied_ReportedToClient()
    {
        await using var h = await AsHarness.StartAsync();
        h.Consent = _ => null;
        var client = h.CreateClient();
        var browser = h.CreateBrowser();

        var error = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RequestAccessAsync(
            AsHarness.PhotoRequest(),
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (i, _) => (await browser.FollowAsync(i.RedirectUri!))!)));

        Assert.Equal(GnapErrorCode.UserDenied, error.Code);
        Assert.Empty(h.TokenStore.Tokens);
    }

    [Fact]
    public async Task TokenRotation_RevocationAndKeyRotation()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var client = h.CreateClient();
        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());
        var original = result.AccessToken!;

        // Rotation: new value, old one revoked.
        var rotated = await client.RotateTokenAsync(original);
        Assert.NotEqual(original.Value, rotated.Value);
        Assert.Equal(2, h.TokenStore.Tokens.Count);
        Assert.Single(h.TokenStore.Tokens, t => !t.Revoked);

        // Rotating the old token again fails: rotation is single-use.
        var reuse = await Assert.ThrowsAsync<GnapProtocolException>(() => client.RotateTokenAsync(original));
        Assert.Equal(GnapErrorCode.InvalidRotation, reuse.Code);

        // Key rotation: the token moves to a new key, proven by both keys.
        var newKey = GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-2"));
        var moved = await client.RotateTokenKeyAsync(rotated, newKey);
        Assert.Same(newKey, moved.BoundKey);
        var active = Assert.Single(h.TokenStore.Tokens, t => !t.Revoked);
        Assert.Equal("client-key-2", active.BoundKey!.Jwk!.Kid);

        // The token is now managed with the new key.
        var again = await client.RotateTokenAsync(moved);
        await client.RevokeTokenAsync(again);
        Assert.All(h.TokenStore.Tokens, t => Assert.True(t.Revoked));
    }

    [Fact]
    public async Task ExpiredToken_IsRefreshedByTokenSource()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var client = h.CreateClient();
        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());
        var source = client.CreateTokenSource(result.AccessToken!);

        h.Time.Advance(TimeSpan.FromHours(2));
        var refreshed = await source.GetTokenAsync();

        Assert.NotEqual(result.AccessToken!.Value, refreshed.Value);
        Assert.False(refreshed.IsExpired(h.Time.GetUtcNow()));
    }

    [Fact]
    public async Task IssuedInstanceId_CanBeUsedByReference()
    {
        await using var h = await AsHarness.StartAsync(context =>
            context.Client.IsRegistered ? GrantDecision.Approve() : GrantDecision.RequireInteraction());
        var jwk = AsHarness.NewEcKey("client-key-1");
        var client = h.CreateClient(jwk);
        var browser = h.CreateBrowser();
        var first = await client.RequestAccessAsync(
            AsHarness.PhotoRequest(),
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (i, _) => (await browser.FollowAsync(i.RedirectUri!))!));

        // The registered instance is approved by policy without interaction.
        var registered = h.CreateClient(jwk, o => o.InstanceId = first.InstanceId);
        var second = await registered.RequestAccessAsync(AsHarness.PhotoRequest());

        Assert.NotNull(second.AccessToken);
        Assert.Null(second.InstanceId);
        Assert.Single(h.ConsentShown);
    }

    [Fact]
    public async Task KeyReference_ResolvedThroughClientKeyStore()
    {
        await using var h = await AsHarness.StartAsync(context =>
            context.Client.IsRegistered ? GrantDecision.Approve() : GrantDecision.Deny());
        var jwk = AsHarness.NewEcKey("client-key-1");
        h.ClientKeys.AddKeyReference("key-ref-1", Gnap.Core.Keys.GnapKey.ForHttpSig(jwk));
        var client = h.CreateClient(jwk, o => o.ClientKey = GnapClientKey.FromJwk(jwk).WithReference("key-ref-1"));

        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());

        Assert.NotNull(result.AccessToken);
    }

    [Fact]
    public async Task GrantRevocation_RevokesItsTokens()
    {
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve());
        var client = h.CreateClient();
        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());

        await client.Protocol.CancelGrantAsync(result.Continue!, client.ClientKey);

        Assert.All(h.TokenStore.Tokens, t => Assert.True(t.Revoked));
    }

    [Fact]
    public async Task PendingGrant_CanBeCancelled()
    {
        await using var h = await AsHarness.StartAsync();
        var client = h.CreateClient();
        var pending = await client.StartGrantAsync(AsHarness.PhotoRequest(), GnapInteractionHandler.UserCode((_, _) => ValueTask.CompletedTask));

        await pending.CancelAsync();

        // The user code no longer works.
        var browser = h.CreateBrowser();
        await Assert.ThrowsAsync<HttpRequestException>(() => browser.EnterUserCodeAsync(pending.Interaction!.UserCode!));
    }

    [Fact]
    public async Task Discovery_ClientReadsAsMetadata()
    {
        await using var h = await AsHarness.StartAsync(configure: o => o.SubjectIdFormatsSupported = [SubjectIdentifierFormats.Opaque]);
        var client = h.CreateClient();

        var metadata = await client.DiscoverAsync();
        var wellKnown = await client.Discovery.GetWellKnownMetadataAsync(new Uri("http://localhost/"));

        Assert.Equal(AsHarness.GrantEndpoint.AbsoluteUri, metadata.GrantRequestEndpoint);
        Assert.True(metadata.SupportsStartMode(StartModes.Redirect));
        Assert.True(metadata.SupportsStartMode(StartModes.UserCode));
        Assert.True(metadata.SupportsFinishMethod(FinishMethods.Push));
        Assert.Equal(["httpsig"], metadata.KeyProofsSupported);
        Assert.Equal([SubjectIdentifierFormats.Opaque], metadata.SubIdFormatsSupported);
        Assert.True(metadata.KeyRotationSupported);
        Assert.Equal(metadata.GrantRequestEndpoint, wellKnown.GrantRequestEndpoint);
        Assert.Equal("http://localhost/gnap/introspect", wellKnown.AdditionalFields!["introspection_endpoint"].GetString());
    }

    [Fact]
    public async Task JwtTokenFormat_IssuesSignedJwtBoundToClientKey()
    {
        var asKey = AsHarness.NewEcKey("as-signing-key");
        var format = new AuthorizationServer.Tokens.JwtTokenFormat(asKey);
        await using var h = await AsHarness.StartAsync(_ => GrantDecision.Approve(), configureServer: s => s.AddTokenFormat(format));
        var jwk = AsHarness.NewEcKey("client-key-1");
        var client = h.CreateClient(jwk);

        var result = await client.RequestAccessAsync(AsHarness.PhotoRequest());

        var parts = result.AccessToken!.Value.Split('.');
        Assert.Equal(3, parts.Length);
        var header = System.Text.Json.JsonDocument.Parse(System.Buffers.Text.Base64Url.DecodeFromChars(parts[0])).RootElement;
        var payload = System.Text.Json.JsonDocument.Parse(System.Buffers.Text.Base64Url.DecodeFromChars(parts[1])).RootElement;
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.Equal("gnap-at+jwt", header.GetProperty("typ").GetString());
        Assert.Equal("as-signing-key", header.GetProperty("kid").GetString());
        Assert.Equal(AsHarness.GrantEndpoint.AbsoluteUri, payload.GetProperty("iss").GetString());
        Assert.Equal(jwk.ComputeThumbprint(), payload.GetProperty("cnf").GetProperty("jkt").GetString());
        Assert.Equal("photo-api", payload.GetProperty("access")[0].GetProperty("type").GetString());

        var signature = System.Buffers.Text.Base64Url.DecodeFromChars(parts[2]);
        var verifier = format.PublicKey.ToSignatureAlgorithm();
        Assert.True(verifier.Verify(System.Text.Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), signature));

        // JWT tokens are still tracked, so they can be revoked like opaque ones.
        await client.RevokeTokenAsync(result.AccessToken);
        Assert.True(Assert.Single(h.TokenStore.Tokens).Revoked);
    }
}
