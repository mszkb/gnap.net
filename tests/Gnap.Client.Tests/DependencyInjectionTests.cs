using Gnap.Client.Discovery;
using Gnap.Client.Tests.Infrastructure;
using Gnap.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Gnap.Client.Tests;

public class DependencyInjectionTests
{
    [Fact]
    public async Task AddGnapClient_ResolvesWorkingClientOverHttpClientFactory()
    {
        var time = new VirtualTimeProvider();
        using var fakeAs = new FakeAuthorizationServer(time);
        var key = GnapClientKey.FromJwk(ClientHarness.NewEcKey("di-key"));

        var services = new ServiceCollection();
        services.AddGnapClient(options =>
            {
                options.GrantEndpoint = FakeAuthorizationServer.GrantEndpoint;
                options.ClientKey = key;
                options.TimeProvider = time;
            })
            .ConfigurePrimaryHttpMessageHandler(() => new NonDisposingHandler(fakeAs));

        await using var provider = services.BuildServiceProvider();
        var client = provider.GetRequiredService<GnapClient>();
        var result = await client.RequestAccessAsync([AccessRight.ForReference("photo-api")]);
        await client.DiscoverAsync();
        await provider.GetRequiredService<GnapClient>().DiscoverAsync();

        Assert.NotNull(result.AccessToken);
        Assert.Empty(fakeAs.ProofFailures);
        Assert.Equal(1, fakeAs.DiscoveryRequests); // the singleton cache is shared across transient clients
        Assert.Same(provider.GetRequiredService<GnapMetadataCache>(), provider.GetRequiredService<GnapMetadataCache>());
    }

    [Fact]
    public void Client_HasNoAspNetCoreDependency()
    {
        var references = typeof(GnapClient).Assembly.GetReferencedAssemblies();
        Assert.DoesNotContain(references, r => r.Name!.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal));
    }

    private sealed class NonDisposingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        protected override void Dispose(bool disposing)
        {
            // The fake AS outlives the factory's handler rotation.
        }
    }
}
