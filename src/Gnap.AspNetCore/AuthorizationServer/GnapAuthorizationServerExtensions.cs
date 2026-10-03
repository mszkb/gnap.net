using Gnap.AspNetCore.AuthorizationServer.Endpoints;
using Gnap.AspNetCore.AuthorizationServer.Interaction;
using Gnap.AspNetCore.AuthorizationServer.Policy;
using Gnap.AspNetCore.AuthorizationServer.Stores;
using Gnap.AspNetCore.AuthorizationServer.Tokens;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.AuthorizationServer;

/// <summary>Registration of the GNAP authorization server.</summary>
public static class GnapAuthorizationServerExtensions
{
    /// <summary>
    /// Registers the AS services with replaceable defaults: in-memory stores,
    /// <see cref="DenyAllGrantPolicy"/> (deny by default), <see cref="OpaqueTokenFormat"/>
    /// and <see cref="DefaultInteractionPage"/>. Every default is registered with
    /// <c>TryAdd</c>, so services registered before this call win; the returned builder
    /// replaces them after the fact. Map the endpoints with
    /// <see cref="MapGnapAuthorizationServer"/>.
    /// </summary>
    public static GnapAuthorizationServerBuilder AddGnapAuthorizationServer(
        this IServiceCollection services,
        Action<GnapAuthorizationServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        var options = services.AddOptions<GnapAuthorizationServerOptions>();
        if (configure is not null)
        {
            options.Configure(configure);
        }

        services.AddRouting();
        services.AddLogging();
        services.AddHttpClient(GnapAuthorizationServerOptions.PushHttpClientName);

        services.TryAddSingleton<IGrantStore, InMemoryGrantStore>();
        services.TryAddSingleton<ITokenStore, InMemoryTokenStore>();
        services.TryAddSingleton<IClientKeyStore, InMemoryClientKeyStore>();
        services.TryAddSingleton<IResourceServerStore, InMemoryResourceServerStore>();
        services.TryAddSingleton<IResourceSetStore, InMemoryResourceSetStore>();
        services.TryAddSingleton<IGrantPolicy, DenyAllGrantPolicy>();
        services.TryAddSingleton<ITokenFormat, OpaqueTokenFormat>();
        services.TryAddSingleton<IGnapInteractionPage, DefaultInteractionPage>();

        services.TryAddSingleton<GnapEndpointUris>();
        services.TryAddSingleton<KeyProofVerifier>();
        services.TryAddScoped<GnapInteractionService>();
        services.TryAddScoped<IGnapInteractionService>(sp => sp.GetRequiredService<GnapInteractionService>());
        services.TryAddScoped<GrantIssuer>();
        services.TryAddScoped<GrantEndpoint>();
        services.TryAddScoped<ContinuationEndpoint>();
        services.TryAddScoped<TokenManagementEndpoint>();
        services.TryAddScoped<IntrospectionEndpoint>();
        services.TryAddScoped<ResourceRegistrationEndpoint>();
        services.TryAddScoped<DiscoveryEndpoint>();
        services.TryAddScoped<InteractionEndpoint>();
        return new GnapAuthorizationServerBuilder(services);
    }

    /// <summary>
    /// Maps the AS endpoints below <see cref="GnapAuthorizationServerOptions.BasePath"/>
    /// (grant <c>/tx</c>, <c>/continue/{grantId}</c>, <c>/interact/{interactionId}</c>,
    /// <c>/device</c>, <c>/token/{manageId}</c>, <c>/introspect</c>, <c>/resource</c>) plus
    /// <c>/.well-known/gnap-as-rs</c> at the application root.
    /// </summary>
    public static IEndpointConventionBuilder MapGnapAuthorizationServer(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<GnapAuthorizationServerOptions>>().Value;
        var group = endpoints.MapGroup(options.BasePath);

        group.MapPost(GnapPaths.Grant, Handle<GrantEndpoint>((e, c) => e.HandleAsync(c)));
        group.MapMethods(GnapPaths.Grant, [HttpMethods.Options], Handle<DiscoveryEndpoint>((e, c) => e.HandleAsync(c)));
        group.MapPost(GnapPaths.ContinuePrefix + "/{grantId}", Handle<ContinuationEndpoint>((e, c) => e.ContinueAsync(c)));
        group.MapDelete(GnapPaths.ContinuePrefix + "/{grantId}", Handle<ContinuationEndpoint>((e, c) => e.RevokeAsync(c)));
        group.MapPatch(GnapPaths.ContinuePrefix + "/{grantId}", Handle<ContinuationEndpoint>((e, c) => e.ModifyAsync(c)));
        group.MapGet(GnapPaths.InteractPrefix + "/{interactionId}", Handle<InteractionEndpoint>((e, c) => e.StartAsync(c)));
        group.MapGet(GnapPaths.UserCode, Handle<InteractionEndpoint>((e, c) => e.ShowUserCodeFormAsync(c)));
        group.MapPost(GnapPaths.UserCode, Handle<InteractionEndpoint>((e, c) => e.SubmitUserCodeAsync(c)));
        if (options.EnableTokenManagement)
        {
            group.MapPost(GnapPaths.TokenPrefix + "/{manageId}", Handle<TokenManagementEndpoint>((e, c) => e.RotateAsync(c)));
            group.MapDelete(GnapPaths.TokenPrefix + "/{manageId}", Handle<TokenManagementEndpoint>((e, c) => e.RevokeAsync(c)));
        }

        if (options.EnableIntrospection)
        {
            group.MapPost(GnapPaths.Introspect, Handle<IntrospectionEndpoint>((e, c) => e.HandleAsync(c)));
        }

        if (options.EnableResourceRegistration)
        {
            group.MapPost(GnapPaths.ResourceRegistration, Handle<ResourceRegistrationEndpoint>((e, c) => e.HandleAsync(c)));
        }

        endpoints.MapGet(GnapPaths.WellKnown, Handle<DiscoveryEndpoint>((e, c) => e.HandleAsync(c)));
        return group;
    }

    private static RequestDelegate Handle<TEndpoint>(Func<TEndpoint, HttpContext, Task> handle)
        where TEndpoint : notnull =>
        context => handle(context.RequestServices.GetRequiredService<TEndpoint>(), context);
}

/// <summary>Replaces the AS's pluggable services (policy, stores, token format, interaction UI).</summary>
public sealed class GnapAuthorizationServerBuilder
{
    internal GnapAuthorizationServerBuilder(IServiceCollection services) => Services = services;

    /// <summary>The service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>Uses <typeparamref name="TPolicy"/> (scoped) as the grant policy.</summary>
    public GnapAuthorizationServerBuilder AddGrantPolicy<TPolicy>()
        where TPolicy : class, IGrantPolicy => Replace<IGrantPolicy, TPolicy>();

    /// <summary>Uses the given policy instance as the grant policy.</summary>
    public GnapAuthorizationServerBuilder AddGrantPolicy(IGrantPolicy policy) => Replace(policy);

    /// <summary>Uses a delegate as the grant policy.</summary>
    public GnapAuthorizationServerBuilder AddGrantPolicy(Func<GrantPolicyContext, GrantDecision> evaluate) =>
        Replace<IGrantPolicy>(new DelegateGrantPolicy(evaluate));

    /// <summary>Uses <typeparamref name="TStore"/> (scoped) as the grant store.</summary>
    public GnapAuthorizationServerBuilder AddGrantStore<TStore>()
        where TStore : class, IGrantStore => Replace<IGrantStore, TStore>();

    /// <summary>Uses the given grant store instance.</summary>
    public GnapAuthorizationServerBuilder AddGrantStore(IGrantStore store) => Replace(store);

    /// <summary>Uses the given token store instance.</summary>
    public GnapAuthorizationServerBuilder AddTokenStore(ITokenStore store) => Replace(store);

    /// <summary>Uses <typeparamref name="TStore"/> (scoped) as the token store.</summary>
    public GnapAuthorizationServerBuilder AddTokenStore<TStore>()
        where TStore : class, ITokenStore => Replace<ITokenStore, TStore>();

    /// <summary>Uses <typeparamref name="TStore"/> (scoped) as the client key store.</summary>
    public GnapAuthorizationServerBuilder AddClientKeyStore<TStore>()
        where TStore : class, IClientKeyStore => Replace<IClientKeyStore, TStore>();

    /// <summary>Uses the given client key store instance, e.g. a pre-filled <see cref="InMemoryClientKeyStore"/>.</summary>
    public GnapAuthorizationServerBuilder AddClientKeyStore(IClientKeyStore store) => Replace(store);

    /// <summary>Uses the given resource server store instance, e.g. a pre-filled <see cref="InMemoryResourceServerStore"/>.</summary>
    public GnapAuthorizationServerBuilder AddResourceServerStore(IResourceServerStore store) => Replace(store);

    /// <summary>Uses <typeparamref name="TStore"/> (scoped) as the resource server store.</summary>
    public GnapAuthorizationServerBuilder AddResourceServerStore<TStore>()
        where TStore : class, IResourceServerStore => Replace<IResourceServerStore, TStore>();

    /// <summary>Uses the given resource set store instance (RFC 9767 resource registration).</summary>
    public GnapAuthorizationServerBuilder AddResourceSetStore(IResourceSetStore store) => Replace(store);

    /// <summary>Uses <typeparamref name="TStore"/> (scoped) as the resource set store.</summary>
    public GnapAuthorizationServerBuilder AddResourceSetStore<TStore>()
        where TStore : class, IResourceSetStore => Replace<IResourceSetStore, TStore>();

    /// <summary>Uses the given token format, e.g. a <see cref="JwtTokenFormat"/>.</summary>
    public GnapAuthorizationServerBuilder AddTokenFormat(ITokenFormat format) => Replace(format);

    /// <summary>Uses <typeparamref name="TPage"/> (scoped) for the browser-facing interaction pages.</summary>
    public GnapAuthorizationServerBuilder AddInteractionPage<TPage>()
        where TPage : class, IGnapInteractionPage => Replace<IGnapInteractionPage, TPage>();

    private GnapAuthorizationServerBuilder Replace<TService, TImplementation>()
        where TService : class
        where TImplementation : class, TService
    {
        Services.Replace(ServiceDescriptor.Scoped<TService, TImplementation>());
        return this;
    }

    private GnapAuthorizationServerBuilder Replace<TService>(TService instance)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(instance);
        Services.Replace(ServiceDescriptor.Singleton(instance));
        return this;
    }
}
