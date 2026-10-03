using System.Security.Cryptography;
using Gnap.Core.Keys;
using Gnap.Core.Models;

namespace Gnap.Client.Tests.Infrastructure;

/// <summary>A client wired to a fresh <see cref="FakeAuthorizationServer"/> on virtual time.</summary>
internal sealed class ClientHarness : IDisposable
{
    private ClientHarness(Action<GnapClientOptions>? configure)
    {
        Time = new VirtualTimeProvider();
        As = new FakeAuthorizationServer(Time);
        Http = new HttpClient(As, disposeHandler: false);
        Jwk = NewEcKey("client-key-1");
        Key = GnapClientKey.FromJwk(Jwk);
        Options = new GnapClientOptions
        {
            GrantEndpoint = FakeAuthorizationServer.GrantEndpoint,
            ClientKey = Key,
            Display = new ClientDisplay { Name = "Test Client" },
            TimeProvider = Time,
        };
        configure?.Invoke(Options);
        Client = new GnapClient(Http, Options);
    }

    public VirtualTimeProvider Time { get; }

    public FakeAuthorizationServer As { get; }

    public HttpClient Http { get; }

    public JsonWebKey Jwk { get; }

    public GnapClientKey Key { get; }

    public GnapClientOptions Options { get; }

    public GnapClient Client { get; }

    public static ClientHarness Create(Action<GnapClientOptions>? configure = null) => new(configure);

    public static JsonWebKey NewEcKey(string kid)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: kid);
    }

    public static GrantRequest PhotoRequest(InteractRequest? interact = null) => new()
    {
        AccessToken =
        [
            new AccessTokenRequest
            {
                Access =
                [
                    new AccessRight { Type = "photo-api", Actions = ["read", "write"], Locations = ["https://rs.example/api"] },
                ],
            },
        ],
        Interact = interact,
    };

    /// <summary>Asserts that the AS verified every request it got and saw no bad signature.</summary>
    public void AssertAllRequestsVerified(int atLeast = 1)
    {
        Xunit.Assert.Empty(As.ProofFailures);
        Xunit.Assert.True(As.VerifiedRequests >= atLeast, $"Expected at least {atLeast} verified requests, got {As.VerifiedRequests}.");
    }

    public void Dispose()
    {
        Http.Dispose();
        As.Dispose();
    }
}
