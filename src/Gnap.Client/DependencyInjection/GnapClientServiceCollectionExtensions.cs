using Gnap.Client;
using Gnap.Client.Discovery;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>Registers <see cref="GnapClient"/> with dependency injection.</summary>
public static class GnapClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="GnapClient"/> (transient, on a named
    /// <see cref="IHttpClientFactory"/> client <see cref="GnapClient.HttpClientName"/>)
    /// and a singleton <see cref="GnapMetadataCache"/>.
    /// </summary>
    /// <returns>The HTTP client builder, to add handlers or configure the primary handler.</returns>
    public static IHttpClientBuilder AddGnapClient(this IServiceCollection services, Action<GnapClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.TryAddSingleton(sp => new GnapMetadataCache(sp.GetRequiredService<IOptions<GnapClientOptions>>().Value.TimeProvider));
        services.TryAddTransient(sp => new GnapClient(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(GnapClient.HttpClientName),
            sp.GetRequiredService<IOptions<GnapClientOptions>>().Value,
            sp.GetRequiredService<GnapMetadataCache>()));
        return services.AddHttpClient(GnapClient.HttpClientName);
    }
}
