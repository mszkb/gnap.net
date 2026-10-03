using System.Net;
using System.Text;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.ResourceServer;
using Gnap.AspNetCore.Tests.Infrastructure;
using Gnap.Client;
using Gnap.Client.Tokens;
using Gnap.Client.Discovery;
using Gnap.Client.Interaction;
using Gnap.Core.Models;
using Gnap.HttpMessageSignatures;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.AspNetCore.Tests;

/// <summary>
/// The RS middleware with the four roles end to end: the Phase 2 client obtains a token
/// from the Phase 3 AS (RO consent simulated) and calls the protected RS, which verifies
/// the token (introspection, co-hosted token store, or local JWT) and its key proof.
/// </summary>
public class ResourceServerEndToEndTests
{
    public static TheoryData<TokenValidation> Modes => [TokenValidation.Introspection, TokenValidation.LocalStore, TokenValidation.Jwt];

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task FourRoles_RsFirstDiscovery_Consent_ProtectedResource(TokenValidation mode)
    {
        await using var rs = await RsHarness.StartAsync(mode, policy: _ => GrantDecision.RequireInteraction());

        // 1. The client calls the RS without a token and learns where to ask (RFC 9635 Section 9.1).
        using var anonymous = await rs.Http.GetAsync(RsHarness.Photos);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.True(GnapResourceChallenge.TryParse(anonymous, out var challenge));
        Assert.Equal(AsHarness.GrantEndpoint, challenge.AsUri);
        Assert.NotNull(challenge.Access);

        // The RS registered its resource set at the AS (RFC 9767 Section 3.4) to get that reference.
        var set = await rs.As.Services.GetRequiredService<IResourceSetStore>().FindAsync(challenge.Access);
        Assert.NotNull(set);
        Assert.Equal(RsHarness.ResourceServerId, set.ResourceServerId);

        // 2. The client requests the reference; the RO approves on the consent page.
        rs.As.Consent = _ => new GrantApproval { ResourceOwner = "alice", Access = [set.Access] };
        var client = rs.As.CreateClient();
        var browser = rs.As.CreateBrowser();
        var result = await client.RequestAccessAsync(
            [AccessRight.ForReference(challenge.Access)],
            GnapInteractionHandler.Redirect(AsHarness.Callback, async (i, _) => (await browser.FollowAsync(i.RedirectUri!))!));
        var token = result.AccessToken!;
        Assert.False(token.IsBearer);

        // 3. The client presents the key-bound token with a signature; the RS verifies both.
        using var api = rs.CreateApiClient(client, token);
        using var photos = await api.GetAsync(RsHarness.Photos);
        Assert.Equal(HttpStatusCode.OK, photos.StatusCode);
        Assert.Equal("photos of alice", await photos.Content.ReadAsStringAsync());

        using var whoami = await api.GetAsync(RsHarness.WhoAmI);
        Assert.Equal($"alice|{result.InstanceId}|False|1", await whoami.Content.ReadAsStringAsync());

        // 4. Rights the token does not carry: 403 with a challenge naming the AS.
        using var delete = await api.DeleteAsync(RsHarness.Photos);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        Assert.True(GnapResourceChallenge.TryParse(delete, out var forbidden));
        Assert.Equal(AsHarness.GrantEndpoint, forbidden.AsUri);
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task SignedRequestWithBody_DigestVerified_BodyStillReadable(TokenValidation mode)
    {
        await using var rs = await RsHarness.StartAsync(mode);
        var (client, token) = await rs.GetTokenAsync(rights: new AccessRight { Type = "photo-api", Actions = ["read", "write"] });
        using var api = rs.CreateApiClient(client, token);

        using var response = await api.PostAsync(RsHarness.Photos, new StringContent("""{"title":"sunset"}""", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("""stored {"title":"sunset"}""", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [MemberData(nameof(Modes))]
    public async Task ExpiredToken_IsRejected(TokenValidation mode)
    {
        await using var rs = await RsHarness.StartAsync(mode);
        var (client, token) = await rs.GetTokenAsync();
        using (var fresh = await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, token.Value, client.ClientKey))
        {
            Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        }

        rs.As.Time.Advance(TimeSpan.FromHours(1) + TimeSpan.FromSeconds(1));

        using var expired = await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, token.Value, client.ClientKey);
        Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode);
    }

    [Theory]
    [InlineData(TokenValidation.Introspection, false)]
    [InlineData(TokenValidation.Introspection, true)]
    [InlineData(TokenValidation.LocalStore, false)]
    [InlineData(TokenValidation.LocalStore, true)]
    [InlineData(TokenValidation.Jwt, false)]
    [InlineData(TokenValidation.Jwt, true)]
    public async Task BearerTokens_OnlyWhenAllowed(TokenValidation mode, bool allowBearer)
    {
        await using var rs = await RsHarness.StartAsync(mode, o => o.AllowBearerTokens = allowBearer, o => o.AllowBearerTokens = true);
        var (_, token) = await rs.GetTokenAsync(bearer: true);
        Assert.True(token.IsBearer);

        using var response = await rs.SendAsync(HttpMethod.Get, RsHarness.WhoAmI, token.Value, signer: null);

        Assert.Equal(allowBearer ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, response.StatusCode);
        if (allowBearer)
        {
            Assert.EndsWith("|True|1", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }
}

/// <summary>Acceptance criterion: a key-bound token without a valid request signature is always rejected.</summary>
public class ResourceServerKeyProofTests
{
    public static TheoryData<TokenValidation, string> Cases()
    {
        var data = new TheoryData<TokenValidation, string>();
        foreach (var mode in new[] { TokenValidation.Introspection, TokenValidation.LocalStore, TokenValidation.Jwt })
        {
            foreach (var attack in new[] { "unsigned", "wrong-key", "stolen-token", "tampered-body", "tampered-body-and-digest", "swapped-token", "stale", "no-nonce" })
            {
                data.Add(mode, attack);
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task KeyBoundToken_WithoutValidSignature_IsRejected(TokenValidation mode, string attack)
    {
        await using var rs = await RsHarness.StartAsync(mode, configureAs: o => o.AllowBearerTokens = true);
        var (client, token) = await rs.GetTokenAsync(rights: new AccessRight { Type = "photo-api", Actions = ["read", "write"] });
        var (other, otherToken) = await rs.GetTokenAsync();
        const string Body = """{"title":"sunset"}""";

        using var response = attack switch
        {
            "unsigned" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, null, Body),
            // Another key with the same kid as the client's.
            "wrong-key" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, GnapClientKey.FromJwk(AsHarness.NewEcKey("client-key-1")), Body),
            // Another client signs correctly with its own key but presents this token.
            "stolen-token" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, other.ClientKey, Body),
            "tampered-body" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, Body, r => ReplaceBody(r, """{"title":"evil"}""", keepDigest: true)),
            "tampered-body-and-digest" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, Body, r => ReplaceBody(r, """{"title":"evil"}""", keepDigest: false)),
            // The signature covers the Authorization field: presenting another token breaks it.
            "swapped-token" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, Body, r => Core.GnapAuthorization.Apply(r, otherToken.Value)),
            "stale" => await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, Body, clock: new FixedTimeProvider(rs.As.Time.GetUtcNow().AddMinutes(-11))),
            "no-nonce" => await SendWithoutNonceAsync(rs, token.Value, client, Body),
            _ => throw new ArgumentOutOfRangeException(nameof(attack)),
        };

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(GnapResourceChallenge.TryParse(response, out _));
        Assert.Equal(string.Empty, await response.Content.ReadAsStringAsync());

        // The legitimate request still works.
        using var valid = await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, Body);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
    }

    [Theory]
    [InlineData(TokenValidation.Introspection)]
    [InlineData(TokenValidation.LocalStore)]
    [InlineData(TokenValidation.Jwt)]
    public async Task ReplayedRequest_IsRejected(TokenValidation mode)
    {
        await using var rs = await RsHarness.StartAsync(mode);
        var (client, token) = await rs.GetTokenAsync();
        using var original = RawRequests.Create(HttpMethod.Get, RsHarness.Photos, token.Value, null);
        await client.ClientKey.CreateProofer(rs.As.Time).AddProofAsync(original);
        using var replay = await RawRequests.CloneAsync(original);

        using var first = await rs.Http.SendAsync(original);
        using var second = await rs.Http.SendAsync(replay);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, second.StatusCode);
    }

    [Theory]
    [InlineData("GNAP")]
    [InlineData("GNAP !!not-token68!!")]
    [InlineData("GNAP unknown-token")]
    [InlineData("Bearer some-oauth-token")]
    public async Task MissingMalformedOrUnknownToken_Is401WithChallenge(string authorization)
    {
        await using var rs = await RsHarness.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, RsHarness.Photos);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);

        using var response = await rs.Http.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(GnapResourceChallenge.TryParse(response, out var challenge));
        Assert.Equal(AsHarness.GrantEndpoint, challenge.AsUri);
    }

    [Fact]
    public async Task OversizedBody_IsRejected()
    {
        await using var rs = await RsHarness.StartAsync(configure: o => o.MaxRequestBodySize = 16);
        var (client, token) = await rs.GetTokenAsync(rights: new AccessRight { Type = "photo-api", Actions = ["write"] });

        using var response = await rs.SendAsync(HttpMethod.Post, RsHarness.Photos, token.Value, client.ClientKey, new string('x', 64));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static void ReplaceBody(HttpRequestMessage request, string body, bool keepDigest)
    {
        var digest = request.Content!.Headers.GetValues("Content-Digest").Single();
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        request.Content.Headers.TryAddWithoutValidation(
            "Content-Digest",
            keepDigest ? digest : HttpMessageSignatures.ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(body), HttpMessageSignatures.ContentDigestAlgorithm.Sha256));
    }

    private static async Task<HttpResponseMessage> SendWithoutNonceAsync(RsHarness rs, string token, GnapClient client, string body)
    {
        using var request = RawRequests.Create(HttpMethod.Post, RsHarness.Photos, token, body);
        request.Content!.Headers.TryAddWithoutValidation(
            "Content-Digest",
            HttpMessageSignatures.ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(body), HttpMessageSignatures.ContentDigestAlgorithm.Sha256));
        new HttpMessageSignatures.HttpMessageSigner(client.ClientKey.Algorithm)
        {
            KeyId = client.ClientKey.KeyId,
            CoveredComponents =
            [
                HttpMessageSignatures.SignatureComponent.Method,
                HttpMessageSignatures.SignatureComponent.TargetUri,
                HttpMessageSignatures.SignatureComponent.ContentDigest,
                HttpMessageSignatures.SignatureComponent.Field("authorization"),
            ],
            IncludeCreated = true,
            IncludeAlgorithm = false,
            NonceLength = null,
            Tag = Core.GnapConstants.HttpSignatureTag,
            TimeProvider = rs.As.Time,
        }.Sign(request);
        return await rs.Http.SendAsync(request);
    }
}

/// <summary>Revocation and introspection caching.</summary>
public class ResourceServerRevocationAndCachingTests
{
    [Fact]
    public async Task Introspection_CacheHit_ThenExpiry_ThenRevocationVisible()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Introspection);
        var (client, token) = await rs.GetTokenAsync();

        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));
        Assert.Equal(1, rs.Introspections); // miss, then hit

        await client.RevokeTokenAsync(token);
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token)); // still cached
        Assert.Equal(1, rs.Introspections);

        rs.As.Time.Advance(TimeSpan.FromSeconds(61)); // past IntrospectionCacheDuration
        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));
        Assert.Equal(2, rs.Introspections);
    }

    [Fact]
    public async Task Introspection_InvalidateAfterRevocation_IsImmediate()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Introspection);
        var (client, token) = await rs.GetTokenAsync();
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));

        await client.RevokeTokenAsync(token);
        rs.Cache.Invalidate(token.Value);

        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));
        Assert.Equal(2, rs.Introspections);
    }

    [Fact]
    public async Task Introspection_NegativeResultsAreCachedBriefly()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Introspection);
        var (client, _) = await rs.GetTokenAsync();

        using (await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, "unknown-token", client.ClientKey))
        using (await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, "unknown-token", client.ClientKey))
        {
            Assert.Equal(1, rs.Introspections);
        }

        rs.As.Time.Advance(TimeSpan.FromSeconds(11));
        using (await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, "unknown-token", client.ClientKey))
        {
            Assert.Equal(2, rs.Introspections);
        }
    }

    [Fact]
    public async Task Introspection_Disabled_Cache_AlwaysAsks()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Introspection, o => o.IntrospectionCacheDuration = TimeSpan.Zero);
        var (client, token) = await rs.GetTokenAsync();

        await GetAsync(rs, client, token);
        await GetAsync(rs, client, token);

        Assert.Equal(2, rs.Introspections);
        Assert.Equal(0, rs.Cache.Count);
    }

    [Fact]
    public async Task Introspection_UnauthenticatedRs_RejectsTokensWithoutCaching()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Introspection, o => o.ResourceServerId = "not-registered");
        var (client, token) = await rs.GetTokenAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));

        Assert.Equal(2, rs.Introspections);
        Assert.Equal(0, rs.Cache.Count);
    }

    [Fact]
    public async Task LocalStore_RevocationIsImmediate()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.LocalStore);
        var (client, token) = await rs.GetTokenAsync();
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));

        await client.RevokeTokenAsync(token);

        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));
        Assert.Equal(0, rs.Introspections);
    }

    [Fact]
    public async Task LocalStore_GrantRevocationRevokesTokens()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.LocalStore);
        var client = rs.As.CreateClient();
        var result = await client.RequestAccessAsync([RsHarness.PhotoRead]);
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, result.AccessToken!));

        var store = rs.As.TokenStore;
        await store.RevokeByGrantAsync(Assert.Single(store.Tokens).GrantId);

        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, result.AccessToken!));
    }

    [Fact]
    public async Task Jwt_IsVerifiedWithoutCallingTheAs_RevocationOnlyViaExpiry()
    {
        await using var rs = await RsHarness.StartAsync(TokenValidation.Jwt);
        var (client, token) = await rs.GetTokenAsync();
        Assert.Equal(3, token.Value.Split('.').Length);

        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));
        Assert.Equal(0, rs.Introspections);

        // Documented limitation of local JWT validation: revocation is not visible...
        await client.RevokeTokenAsync(token);
        Assert.Equal(HttpStatusCode.OK, await GetAsync(rs, client, token));

        // ...but expiry is.
        rs.As.Time.Advance(TimeSpan.FromHours(2));
        Assert.Equal(HttpStatusCode.Unauthorized, await GetAsync(rs, client, token));
    }

    [Fact]
    public void Cache_EntriesNeverOutliveTheToken()
    {
        var time = new VirtualTimeProvider();
        var cache = new GnapIntrospectionCache(time);
        var info = new GnapTokenInfo { ExpiresAt = time.GetUtcNow().AddSeconds(30) };

        cache.Set("token", info, TimeSpan.FromMinutes(5));
        Assert.True(cache.TryGet("token", out var hit));
        Assert.Same(info, hit);

        time.Advance(TimeSpan.FromSeconds(30));
        Assert.False(cache.TryGet("token", out _));

        cache.Set("expired", new GnapTokenInfo { ExpiresAt = time.GetUtcNow() }, TimeSpan.FromMinutes(1));
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void Cache_IsBounded()
    {
        var time = new VirtualTimeProvider();
        var cache = new GnapIntrospectionCache(time, capacity: 2);
        cache.Set("a", null, TimeSpan.FromSeconds(1));
        cache.Set("b", new GnapTokenInfo(), TimeSpan.FromMinutes(1));
        time.Advance(TimeSpan.FromSeconds(2));

        cache.Set("c", new GnapTokenInfo(), TimeSpan.FromMinutes(1)); // prunes the expired "a"
        Assert.Equal(2, cache.Count);
        Assert.True(cache.TryGet("b", out _));

        cache.Set("d", new GnapTokenInfo(), TimeSpan.FromMinutes(1)); // full of live entries: reset
        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGet("d", out _));
    }

    private static async Task<HttpStatusCode> GetAsync(RsHarness rs, GnapClient client, GnapAccessToken token)
    {
        using var response = await rs.SendAsync(HttpMethod.Get, RsHarness.Photos, token.Value, client.ClientKey);
        return response.StatusCode;
    }
}
