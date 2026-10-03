using Gnap.Core.Keys;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Gnap.AspNetCore.ResourceServer;

/// <summary>Registration of the GNAP resource server.</summary>
public static class GnapResourceServerExtensions
{
    /// <summary>
    /// Registers the GNAP authentication scheme (<see cref="GnapResourceServerDefaults.AuthenticationScheme"/>),
    /// the <see cref="GnapAccessRequirement"/> handler and, by default, token validation by
    /// introspection at the AS (<see cref="IntrospectionTokenValidator"/>). Choose local
    /// validation with the returned builder. Protect endpoints with
    /// <see cref="RequireGnapAccess{TBuilder}(TBuilder, string, string[])"/> after
    /// <see cref="UseGnapResourceServer"/>.
    /// </summary>
    public static GnapResourceServerBuilder AddGnapResourceServer(
        this IServiceCollection services,
        Action<GnapResourceServerOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddAuthentication()
            .AddScheme<GnapResourceServerOptions, GnapResourceServerHandler>(GnapResourceServerDefaults.AuthenticationScheme, configure);
        services.AddAuthorization();
        services.AddHttpClient(GnapResourceServerDefaults.BackchannelHttpClientName);

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, GnapAccessAuthorizationHandler>());
        services.TryAddSingleton<GnapResourceServerRuntime>();
        services.TryAddSingleton(sp =>
        {
            var options = SchemeOptions(sp);
            return new GnapIntrospectionCache(options.TimeProvider, options.IntrospectionCacheSize);
        });
        services.TryAddSingleton(sp => new GnapAsRsClient(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(GnapResourceServerDefaults.BackchannelHttpClientName),
            SchemeOptions(sp)));
        services.TryAddScoped<IGnapTokenValidator, IntrospectionTokenValidator>();
        return new GnapResourceServerBuilder(services);
    }

    /// <summary>
    /// Adds authentication and authorization to the pipeline (<c>UseAuthentication()</c> +
    /// <c>UseAuthorization()</c>), so that endpoints protected with
    /// <see cref="RequireGnapAccess{TBuilder}(TBuilder, string, string[])"/> verify GNAP tokens.
    /// </summary>
    public static IApplicationBuilder UseGnapResourceServer(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseAuthentication().UseAuthorization();
    }

    /// <summary>
    /// Requires a GNAP access token (key-bound with a valid key proof, unless bearer tokens
    /// are allowed) carrying the access reference <paramref name="typeOrReference"/>, or a
    /// right of that <c>type</c> listing all <paramref name="actions"/>.
    /// </summary>
    public static TBuilder RequireGnapAccess<TBuilder>(this TBuilder builder, string typeOrReference, params string[] actions)
        where TBuilder : IEndpointConventionBuilder =>
        builder.RequireGnapAccess(new GnapAccessRequirement(typeOrReference, actions));

    /// <summary>Requires a GNAP access token satisfying <paramref name="requirement"/>.</summary>
    public static TBuilder RequireGnapAccess<TBuilder>(this TBuilder builder, GnapAccessRequirement requirement)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(requirement);
        return builder.RequireAuthorization(new AuthorizationPolicyBuilder().RequireGnapAccess(requirement).Build());
    }

    /// <summary>Requires a GNAP access token (any rights of access).</summary>
    public static TBuilder RequireGnapToken<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.RequireAuthorization(new AuthorizationPolicyBuilder(GnapResourceServerDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build());
    }

    /// <summary>
    /// Adds the GNAP scheme, an authenticated user and a <see cref="GnapAccessRequirement"/>
    /// to a policy, e.g. <c>options.AddPolicy("photos", p => p.RequireGnapAccess("photo-api", "read"))</c>.
    /// </summary>
    public static AuthorizationPolicyBuilder RequireGnapAccess(this AuthorizationPolicyBuilder builder, string typeOrReference, params string[] actions) =>
        builder.RequireGnapAccess(new GnapAccessRequirement(typeOrReference, actions));

    /// <summary>Adds the GNAP scheme, an authenticated user and <paramref name="requirement"/> to a policy.</summary>
    public static AuthorizationPolicyBuilder RequireGnapAccess(this AuthorizationPolicyBuilder builder, GnapAccessRequirement requirement)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(requirement);
        return builder
            .AddAuthenticationSchemes(GnapResourceServerDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .AddRequirements(requirement);
    }

    /// <summary>The validated GNAP access token of the request, if it was authenticated with one.</summary>
    public static GnapTokenInfo? GetGnapToken(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Features.Get<IGnapTokenFeature>()?.Token;
    }

    internal static GnapResourceServerOptions SchemeOptions(IServiceProvider services) =>
        services.GetRequiredService<IOptionsMonitor<GnapResourceServerOptions>>().Get(GnapResourceServerDefaults.AuthenticationScheme);
}

/// <summary>Selects how the resource server validates tokens.</summary>
public sealed class GnapResourceServerBuilder
{
    internal GnapResourceServerBuilder(IServiceCollection services) => Services = services;

    /// <summary>The service collection.</summary>
    public IServiceCollection Services { get; }

    /// <summary>Validates tokens by (cached) introspection at the AS — the default.</summary>
    public GnapResourceServerBuilder UseIntrospection() =>
        UseTokenValidator<IntrospectionTokenValidator>();

    /// <summary>
    /// Validates tokens locally against the token store of an AS hosted in the same
    /// application (requires <c>AddGnapAuthorizationServer</c>).
    /// </summary>
    public GnapResourceServerBuilder UseLocalTokenStore() =>
        UseTokenValidator<TokenStoreValidator>();

    /// <summary>
    /// Validates JWT access tokens (<see cref="AuthorizationServer.Tokens.JwtTokenFormat"/>)
    /// locally with the AS's public signing key; no AS round trip, but revocation is not visible.
    /// </summary>
    public GnapResourceServerBuilder UseJwtTokens(JsonWebKey signingKey, string? issuer = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        return UseTokenValidator(new JwtTokenValidator([signingKey], issuer));
    }

    /// <summary>Uses <typeparamref name="TValidator"/> (scoped) to validate tokens.</summary>
    public GnapResourceServerBuilder UseTokenValidator<TValidator>()
        where TValidator : class, IGnapTokenValidator
    {
        Services.Replace(ServiceDescriptor.Scoped<IGnapTokenValidator, TValidator>());
        return this;
    }

    /// <summary>Uses the given validator instance.</summary>
    public GnapResourceServerBuilder UseTokenValidator(IGnapTokenValidator validator)
    {
        ArgumentNullException.ThrowIfNull(validator);
        Services.Replace(ServiceDescriptor.Singleton(validator));
        return this;
    }
}
