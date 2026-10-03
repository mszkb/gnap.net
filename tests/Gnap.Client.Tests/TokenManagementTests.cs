using System.Net;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Client.Tokens;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Client.Tests;

public class TokenManagementTests
{
    private static async Task<GnapAccessToken> IssueAsync(ClientHarness h) =>
        (await h.Client.RequestAccessAsync([AccessRight.ForReference("photo-api")])).AccessToken!;

    [Fact]
    public async Task Rotation_ReplacesValueAndInvalidatesOldOne()
    {
        using var h = ClientHarness.Create();
        var token = await IssueAsync(h);

        var rotated = await h.Client.RotateTokenAsync(token);

        Assert.NotEqual(token.Value, rotated.Value);
        Assert.True(h.As.FindToken(token.Value)!.Revoked);
        Assert.False(h.As.FindToken(rotated.Value)!.Revoked);
        Assert.Same(h.Key, rotated.BoundKey);
        Assert.Equal("photo-api", rotated.Access![0].Reference);
        Assert.True(rotated.CanBeManaged);
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public async Task UriOnlyManage_OpenPaymentsForm_RotatesAndRevokesWithTheAccessTokenItself()
    {
        // Regression (Rafiki interop): `manage` as a bare URI, the token authorizes itself.
        using var h = ClientHarness.Create();
        h.As.UriOnlyTokenManagement = true;
        var token = await IssueAsync(h);
        Assert.True(token.Token.Manage!.IsUriOnly);
        Assert.True(token.CanBeManaged);

        var rotated = await h.Client.RotateTokenAsync(token);
        Assert.True(h.As.FindToken(token.Value)!.Revoked);
        Assert.True(rotated.CanBeManaged);

        await h.Client.RevokeTokenAsync(rotated);
        Assert.True(h.As.FindToken(rotated.Value)!.Revoked);
        h.AssertAllRequestsVerified(atLeast: 3);
    }

    [Fact]
    public async Task Revocation_DeletesAtManagementUri()
    {
        using var h = ClientHarness.Create();
        var token = await IssueAsync(h);

        await h.Client.RevokeTokenAsync(token);

        Assert.True(h.As.FindToken(token.Value)!.Revoked);
        Assert.Contains(h.As.Requests, r => r.Method == HttpMethod.Delete && r.Path.StartsWith("/token/", StringComparison.Ordinal));
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public async Task Rotation_WithoutManagement_Throws()
    {
        using var h = ClientHarness.Create();
        h.As.OfferTokenManagement = false;
        var token = await IssueAsync(h);

        Assert.False(token.CanBeManaged);
        await Assert.ThrowsAsync<GnapClientException>(() => h.Client.RotateTokenAsync(token));
    }

    [Fact]
    public async Task Rotation_Refused_IsTyped()
    {
        using var h = ClientHarness.Create();
        var token = await IssueAsync(h);
        h.As.FailNext("/token/", GnapErrorCode.InvalidRotation);

        var e = await Assert.ThrowsAsync<GnapProtocolException>(() => h.Client.RotateTokenAsync(token));
        Assert.Equal(GnapErrorCode.InvalidRotation, e.Code);
    }

    [Fact]
    public async Task TokenSource_RotatesAutomaticallyOnExpiry()
    {
        using var h = ClientHarness.Create();
        h.As.TokenLifetimeSeconds = 120;
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        var original = source.Current;

        Assert.Same(original, await source.GetTokenAsync());

        h.Time.Advance(TimeSpan.FromSeconds(100)); // inside the 30 s refresh skew
        var refreshed = await source.GetTokenAsync();

        Assert.NotEqual(original.Value, refreshed.Value);
        Assert.Same(refreshed, source.Current);
        Assert.Equal(h.Time.GetUtcNow().AddSeconds(120), refreshed.ExpiresAt);
        Assert.Same(refreshed, await source.GetTokenAsync());
    }

    [Fact]
    public async Task TokenSource_ExpiredWithoutManagement_Throws()
    {
        using var h = ClientHarness.Create();
        h.As.TokenLifetimeSeconds = 60;
        h.As.OfferTokenManagement = false;
        var source = h.Client.CreateTokenSource(await IssueAsync(h));

        h.Time.Advance(TimeSpan.FromMinutes(5));

        await Assert.ThrowsAsync<GnapClientException>(() => source.GetTokenAsync());
    }

    [Fact]
    public async Task TokenSource_ConcurrentRefresh_RotatesOnce()
    {
        using var h = ClientHarness.Create();
        h.As.TokenLifetimeSeconds = 60;
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        h.Time.Advance(TimeSpan.FromMinutes(2));

        var tokens = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => source.GetTokenAsync()));

        Assert.Single(tokens.Select(t => t.Value).Distinct());
        Assert.Single(h.As.Requests, r => r.Path.StartsWith("/token/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Handler_PresentsSignedTokenToResourceServer()
    {
        using var h = ClientHarness.Create();
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        using var rs = new HttpClient(new GnapAccessTokenHandler(source, h.As), disposeHandler: false);

        using var response = await rs.GetAsync(FakeAuthorizationServer.ResourceUri);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        h.AssertAllRequestsVerified(atLeast: 2);
    }

    [Fact]
    public async Task Handler_RotatesExpiredTokenBeforeSending()
    {
        using var h = ClientHarness.Create();
        h.As.TokenLifetimeSeconds = 60;
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        using var rs = new HttpClient(new GnapAccessTokenHandler(source, h.As), disposeHandler: false);
        h.Time.Advance(TimeSpan.FromMinutes(2));

        using var response = await rs.GetAsync(FakeAuthorizationServer.ResourceUri);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(["/tx", $"/token/{h.As.Requests[1].Path["/token/".Length..]}", "/api/photos"], h.As.Requests.Select(r => r.Path));
    }

    [Fact]
    public async Task Handler_RotatesAndRetriesOnUnauthorized_WithBody()
    {
        using var h = ClientHarness.Create();
        h.As.TokenLifetimeSeconds = null; // the client cannot see expiry coming
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        using var rs = new HttpClient(new GnapAccessTokenHandler(source, h.As), disposeHandler: false);
        h.As.ExpireAllTokens();

        using var response = await rs.PostAsync(FakeAuthorizationServer.ResourceUri, new StringContent("{\"title\":\"sunset\"}"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, h.As.Requests.Count(r => r.Path == "/api/photos"));
        h.AssertAllRequestsVerified(atLeast: 3);
    }

    [Fact]
    public async Task Handler_BearerToken_IsSentWithoutSignature()
    {
        using var h = ClientHarness.Create();
        var result = await h.Client.RequestAccessAsync(new GrantRequest
        {
            AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("public")], Flags = [AccessTokenFlags.Bearer] }],
        });
        var source = h.Client.CreateTokenSource(result.AccessToken!);
        HttpRequestMessage? sent = null;
        h.As.Intercept(request =>
        {
            if (request.RequestUri!.Host != "rs.example")
            {
                return null;
            }

            sent = request;
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        using var rs = new HttpClient(new GnapAccessTokenHandler(source, h.As), disposeHandler: false);

        using var response = await rs.GetAsync(FakeAuthorizationServer.ResourceUri);

        Assert.Equal($"GNAP {result.AccessToken!.Value}", sent!.Headers.Authorization!.ToString());
        Assert.False(sent.Headers.Contains("Signature"));
    }

    [Fact]
    public async Task KeyRotation_ProvesBothKeysAndRebindsToken()
    {
        using var h = ClientHarness.Create();
        var source = h.Client.CreateTokenSource(await IssueAsync(h));
        var newKey = GnapClientKey.FromJwk(ClientHarness.NewEcKey("client-key-2"));

        var rotated = await source.RotateKeyAsync(newKey);

        Assert.Same(newKey, rotated.BoundKey);
        Assert.Same(newKey, rotated.ManagementKey);
        Assert.Contains("sig1=", h.As.LastRotationSignatureInput, StringComparison.Ordinal);
        Assert.Contains("sig2=", h.As.LastRotationSignatureInput, StringComparison.Ordinal);
        Assert.Contains("\"signature-input\";key=\"sig1\"", h.As.LastRotationSignatureInput, StringComparison.Ordinal);
        Assert.Equal("client-key-2", h.As.FindToken(rotated.Value)!.BoundKey!.Kid);

        // The token now works with (only) the new key, and can be managed with it.
        using var rs = new HttpClient(new GnapAccessTokenHandler(source, h.As), disposeHandler: false);
        using var response = await rs.GetAsync(FakeAuthorizationServer.ResourceUri);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await source.RevokeAsync();
        Assert.True(h.As.FindToken(rotated.Value)!.Revoked);
        h.AssertAllRequestsVerified(atLeast: 4);
    }

    [Fact]
    public async Task KeyRotation_NotSupported_IsTyped()
    {
        using var h = ClientHarness.Create();
        var token = await IssueAsync(h);
        h.As.FailNext("/token/", GnapErrorCode.KeyRotationNotSupported);

        var e = await Assert.ThrowsAsync<GnapProtocolException>(
            () => h.Client.RotateTokenKeyAsync(token, GnapClientKey.FromJwk(ClientHarness.NewEcKey("k2"))));
        Assert.Equal(GnapErrorCode.KeyRotationNotSupported, e.Code);
    }

    [Fact]
    public async Task ClientKeyRotation_NewGrantsUseNewKey()
    {
        using var h = ClientHarness.Create();
        var newJwk = ClientHarness.NewEcKey("client-key-2");
        h.Client.UseClientKey(GnapClientKey.FromJwk(newJwk));

        var token = await IssueAsync(h);

        Assert.Equal("client-key-2", h.As.LastGrantRequest!.Client!.Key!.Jwk!.Kid);
        Assert.Equal("client-key-2", token.BoundKey!.KeyId);
        h.AssertAllRequestsVerified();
    }

    [Fact]
    public void IsExpired_HonoursSkew()
    {
        var key = GnapClientKey.FromJwk(ClientHarness.NewEcKey("k"));
        var issued = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var token = new GnapAccessToken(new AccessTokenResponse { Value = "abc", ExpiresIn = 60 }, key, key, issued);

        Assert.False(token.IsExpired(issued.AddSeconds(59)));
        Assert.True(token.IsExpired(issued.AddSeconds(60)));
        Assert.True(token.IsExpired(issued.AddSeconds(31), TimeSpan.FromSeconds(30)));
        Assert.False(new GnapAccessToken(new AccessTokenResponse { Value = "abc" }, key, key, issued).IsExpired(DateTimeOffset.MaxValue.AddDays(-1)));
    }

    [Fact]
    public async Task TokenBoundToForeignKey_CannotBePresented()
    {
        var key = GnapClientKey.FromJwk(ClientHarness.NewEcKey("k"));
        var token = new GnapAccessToken(
            new AccessTokenResponse { Value = "abc", Key = Gnap.Core.Keys.GnapKey.ForReference("other") },
            boundKey: null,
            key,
            DateTimeOffset.UtcNow);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://rs.example/");

        await Assert.ThrowsAsync<GnapClientException>(() => token.ApplyAsync(request));
    }
}
