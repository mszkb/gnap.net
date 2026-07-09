using System.Net;
using System.Text;
using Gnap.HttpMessageSignatures.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// End-to-end tests: an HttpClient signing through
/// <see cref="HttpSignatureDelegatingHandler"/> against the ASP.NET Core
/// verification middleware on an in-memory test server.
/// </summary>
public sealed class MiddlewareIntegrationTests : IAsyncLifetime
{
    private static readonly SignatureComponent[] ClientComponents =
    [
        SignatureComponent.Method,
        SignatureComponent.TargetUri,
        SignatureComponent.ContentDigest,
    ];

    private readonly SignatureAlgorithm _clientKey = RoundtripTests.CreateFreshKey("ed25519");
    private IHost _host = null!;

    public async Task InitializeAsync()
    {
        _host = await new HostBuilder()
            .ConfigureWebHost(webHost => webHost
                .UseTestServer()
                .ConfigureServices(services => services.AddHttpMessageSignatureVerification(options =>
                {
                    options.KeyResolver = new StaticKeyResolver().Add("integration-client", _clientKey);
                    options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];
                }))
                .Configure(app =>
                {
                    app.UseHttpMessageSignatureVerification();
                    app.Run(async context =>
                    {
                        var feature = context.Features.Get<IHttpMessageSignatureFeature>();
                        var keyId = feature?.Result.Signatures[0].Parameters?.KeyId;
                        context.Response.ContentType = "text/plain";
                        await context.Response.WriteAsync($"hello {keyId}");
                    });
                }))
            .StartAsync();
    }

    public async Task DisposeAsync()
    {
        await _host.StopAsync();
        _host.Dispose();
    }

    private HttpClient CreateSigningClient(SignatureAlgorithm? key = null, SignatureComponent[]? components = null)
    {
        var signer = new HttpMessageSigner(key ?? _clientKey)
        {
            KeyId = "integration-client",
            CoveredComponents = components ?? ClientComponents,
            Lifetime = TimeSpan.FromMinutes(5),
        };
        var handler = new HttpSignatureDelegatingHandler(signer, _host.GetTestServer().CreateHandler());
        return new HttpClient(handler) { BaseAddress = _host.GetTestServer().BaseAddress };
    }

    [Fact]
    public async Task SignedRequestWithBody_IsAcceptedAndExposesKeyId()
    {
        using var client = CreateSigningClient();

        var response = await client.PostAsync("/api/data", new StringContent("{\"v\":1}", Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("hello integration-client", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task SignedGetWithoutBody_IsAccepted()
    {
        using var client = CreateSigningClient(components: [SignatureComponent.Method, SignatureComponent.TargetUri]);

        var response = await client.GetAsync("/api/data");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UnsignedRequest_IsRejectedWith401()
    {
        using var client = _host.GetTestServer().CreateClient();

        var response = await client.GetAsync("/api/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Signature", response.Headers.WwwAuthenticate.ToString());
    }

    [Fact]
    public async Task RequestSignedWithUnknownKey_IsRejectedWith401()
    {
        using var client = CreateSigningClient(
            key: RoundtripTests.CreateFreshKey("ed25519"),
            components: [SignatureComponent.Method, SignatureComponent.TargetUri]);

        var response = await client.GetAsync("/api/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task BodyTamperedAfterSigning_IsRejectedWith401()
    {
        // Sign a request for one body, then send different content under the
        // original Content-Digest: the middleware must reject the digest mismatch.
        var signer = new HttpMessageSigner(_clientKey)
        {
            KeyId = "integration-client",
            CoveredComponents = ClientComponents,
        };
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_host.GetTestServer().BaseAddress, "/api/data"))
        {
            Content = new StringContent("{\"v\":1}", Encoding.UTF8, "application/json"),
        };
        request.Content.Headers.TryAddWithoutValidation(
            "Content-Digest",
            ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes("{\"v\":1}")));
        signer.Sign(request);
        request.Content = new StringContent("{\"v\":2}", Encoding.UTF8, "application/json");
        request.Content.Headers.TryAddWithoutValidation(
            "Content-Digest",
            ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes("{\"v\":1}")));

        using var client = new HttpClient(_host.GetTestServer().CreateHandler());
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task BodyWithoutContentDigest_IsRejectedWith401()
    {
        var signer = new HttpMessageSigner(_clientKey)
        {
            KeyId = "integration-client",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        };
        var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_host.GetTestServer().BaseAddress, "/api/data"))
        {
            Content = new StringContent("{\"v\":1}", Encoding.UTF8, "application/json"),
        };
        signer.Sign(request);

        using var client = new HttpClient(_host.GetTestServer().CreateHandler());
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SignatureNotCoveringRequiredComponents_IsRejectedWith401()
    {
        using var client = CreateSigningClient(components: [SignatureComponent.Method]);

        var response = await client.GetAsync("/api/data");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
