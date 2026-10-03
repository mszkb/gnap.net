using System.Net;
using Gnap.Client.Discovery;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Core.Models;
using Xunit;

namespace Gnap.Client.Tests;

public class DiscoveryTests
{
    [Fact]
    public async Task GrantEndpointDiscovery_ParsesAndCaches()
    {
        using var h = ClientHarness.Create();

        var metadata = await h.Client.DiscoverAsync();
        var again = await h.Client.DiscoverAsync();

        Assert.Same(metadata, again);
        Assert.Equal(1, h.As.DiscoveryRequests);
        Assert.Equal(HttpMethod.Options, h.As.Requests.Single().Method);
        Assert.Equal("https://as.example/tx", metadata.GrantRequestEndpoint);
        Assert.True(metadata.SupportsStartMode(StartModes.UserCodeUri));
        Assert.True(metadata.SupportsFinishMethod(FinishMethods.Push));
        Assert.False(metadata.SupportsStartMode(StartModes.App));
        Assert.Equal(["httpsig"], metadata.KeyProofsSupported);
        Assert.Equal(["opaque", "email"], metadata.SubIdFormatsSupported);
        Assert.True(metadata.KeyRotationSupported);
        Assert.Equal("https://as.example/introspect", metadata.AdditionalFields!["introspection_endpoint"].GetString());
    }

    [Fact]
    public async Task Cache_ExpiresAfterDefaultLifetime()
    {
        using var h = ClientHarness.Create(o => o.MetadataCacheDuration = TimeSpan.FromMinutes(10));

        await h.Client.DiscoverAsync();
        h.Time.Advance(TimeSpan.FromMinutes(9));
        await h.Client.DiscoverAsync();
        h.Time.Advance(TimeSpan.FromMinutes(2));
        await h.Client.DiscoverAsync();

        Assert.Equal(2, h.As.DiscoveryRequests);
    }

    [Fact]
    public async Task Cache_HonoursMaxAge()
    {
        using var h = ClientHarness.Create();
        h.As.DiscoveryMaxAge = 30;

        await h.Client.DiscoverAsync();
        h.Time.Advance(TimeSpan.FromSeconds(31));
        await h.Client.DiscoverAsync();

        Assert.Equal(2, h.As.DiscoveryRequests);
    }

    [Fact]
    public async Task SharedCache_IsUsedAcrossClients()
    {
        using var h = ClientHarness.Create();
        var cache = new GnapMetadataCache(h.Time);
        await new GnapClient(h.Http, h.Options, cache).DiscoverAsync();
        await new GnapClient(h.Http, h.Options, cache).DiscoverAsync();

        Assert.Equal(1, h.As.DiscoveryRequests);
        cache.Invalidate(FakeAuthorizationServer.GrantEndpoint);
        await new GnapClient(h.Http, h.Options, cache).DiscoverAsync();
        Assert.Equal(2, h.As.DiscoveryRequests);
    }

    [Fact]
    public async Task WellKnownDiscovery_UsesGnapAsRsPath()
    {
        using var h = ClientHarness.Create();

        var metadata = await h.Client.Discovery.GetWellKnownMetadataAsync(new Uri("https://as.example/some/path?q=1"));

        Assert.Equal("https://as.example/tx", metadata.GrantRequestEndpoint);
        Assert.Equal((HttpMethod.Get, "/.well-known/gnap-as-rs"), h.As.Requests.Single());
    }

    [Fact]
    public async Task Discovery_Failure_IsReported()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.NotFound));

        var e = await Assert.ThrowsAsync<GnapClientException>(() => h.Client.DiscoverAsync());
        Assert.Equal(HttpStatusCode.NotFound, e.StatusCode);
    }

    [Fact]
    public async Task Discovery_WithoutGrantEndpoint_IsRejected()
    {
        using var h = ClientHarness.Create();
        h.As.Intercept(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });

        await Assert.ThrowsAsync<GnapClientException>(() => h.Client.DiscoverAsync());
    }

    [Fact]
    public async Task ResourceServerChallenge_LeadsToAs()
    {
        using var h = ClientHarness.Create();
        using var response = await h.Http.GetAsync(FakeAuthorizationServer.ResourceUri);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(GnapResourceChallenge.TryParse(response, out var challenge));
        Assert.Equal(FakeAuthorizationServer.GrantEndpoint, challenge.AsUri);
        Assert.Equal("photo-api", challenge.Access);
    }

    [Theory]
    [InlineData("GNAP as_uri=https://as.example/tx,access=FWWIKYBQ6U56NL1", "https://as.example/tx", "FWWIKYBQ6U56NL1", null)]
    [InlineData("gnap as_uri=\"https://as.example/tx\", referrer=\"https://rs.example/\"", "https://as.example/tx", null, "https://rs.example/")]
    [InlineData("Bearer realm=\"x\", GNAP as_uri=\"https://as.example/tx\"", "https://as.example/tx", null, null)]
    public void ChallengeParsing(string header, string asUri, string? access, string? referrer)
    {
        Assert.True(GnapResourceChallenge.TryParse(header, out var challenge));
        Assert.Equal(new Uri(asUri), challenge.AsUri);
        Assert.Equal(access, challenge.Access);
        Assert.Equal(referrer, challenge.Referrer);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Bearer realm=\"x\"")]
    [InlineData("GNAP access=abc")]
    [InlineData("GNAP as_uri=\"/relative\"")]
    [InlineData("GNAP as_uri=\"javascript:alert(1)\"")]
    [InlineData("GNAPX as_uri=\"https://as.example/tx\"")]
    public void ChallengeParsing_Rejects(string? header)
    {
        Assert.False(GnapResourceChallenge.TryParse(header, out _));
    }
}
