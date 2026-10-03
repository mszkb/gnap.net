using System.Net;
using System.Text;
using Gnap.HttpMessageSignatures.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Replay protection via the <c>nonce</c> parameter (RFC 9421 Section 7.2.2).</summary>
public class NonceReplayTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 9, 12, 0, 0, TimeSpan.Zero);

    private static SimpleHttpMessage SignedMessage(SignatureAlgorithm key, string keyId = "the-key", int? nonceLength = 16, TimeSpan? lifetime = null)
    {
        var signer = new HttpMessageSigner(key)
        {
            KeyId = keyId,
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            NonceLength = nonceLength,
            Lifetime = lifetime,
            TimeProvider = new FakeTimeProvider(Now),
        };
        var message = SimpleHttpMessage.Request("POST", "https://example.com/api");
        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);
        return message;
    }

    private static SimpleHttpMessage WithNonce(SignatureAlgorithm key, string keyId, string nonce)
    {
        var parameters = new SignatureParameters()
            .AddComponents([SignatureComponent.Method, SignatureComponent.TargetUri])
            .WithCreated(Now)
            .WithKeyId(keyId)
            .WithNonce(nonce);
        var message = SimpleHttpMessage.Request("POST", "https://example.com/api");
        var signature = key.Sign(Encoding.UTF8.GetBytes(SignatureBaseBuilder.Build(message, parameters)));
        message.WithHeader("Signature-Input", $"sig1={parameters.Serialize()}");
        message.WithHeader("Signature", $"sig1=:{Convert.ToBase64String(signature)}:");
        return message;
    }

    private static HttpMessageVerifier Verifier(
        StaticKeyResolver keys,
        INonceStore? store,
        TimeProvider clock,
        bool requireNonce = false,
        TimeSpan? maxAge = null) =>
        new(new VerificationOptions
        {
            KeyResolver = keys,
            NonceStore = store,
            RequireNonce = requireNonce,
            MaxAge = maxAge ?? TimeSpan.FromMinutes(5),
            ClockSkew = TimeSpan.FromMinutes(1),
            TimeProvider = clock,
        });

    [Fact]
    public async Task SameSignedMessageTwice_SecondIsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), new InMemoryNonceStore(clock), clock);
        var message = SignedMessage(key);

        var first = await verifier.VerifyAsync(message);
        Assert.True(first.Succeeded, first.FailureReason);

        var replay = await verifier.VerifyAsync(message);
        Assert.False(replay.Succeeded);
        Assert.Contains("replay", replay.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithoutNonceStore_ReplayIsNotDetected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), store: null, clock);
        var message = SignedMessage(key);

        Assert.True((await verifier.VerifyAsync(message)).Succeeded);
        Assert.True((await verifier.VerifyAsync(message)).Succeeded);
    }

    [Fact]
    public async Task RequireNonce_RejectsSignatureWithoutNonce()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), new InMemoryNonceStore(clock), clock, requireNonce: true);

        var result = await verifier.VerifyAsync(SignedMessage(key, nonceLength: null));
        Assert.False(result.Succeeded);
        Assert.Contains("nonce", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RequireNonce_AcceptsSignatureWithNonce()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), new InMemoryNonceStore(clock), clock, requireNonce: true);

        var result = await verifier.VerifyAsync(SignedMessage(key));
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task InvalidSignature_DoesNotStoreNonce()
    {
        var realKey = RoundtripTests.CreateFreshKey("ed25519");
        var attackerKey = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var store = new InMemoryNonceStore(clock);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", realKey), store, clock);

        // The attacker forges a message carrying the nonce the legitimate client will use.
        var forged = await verifier.VerifyAsync(WithNonce(attackerKey, "the-key", "victim-nonce"));
        Assert.False(forged.Succeeded);
        Assert.Equal(0, store.Count);
        Assert.False(store.Contains("the-key", "victim-nonce"));

        var legitimate = await verifier.VerifyAsync(WithNonce(realKey, "the-key", "victim-nonce"));
        Assert.True(legitimate.Succeeded, legitimate.FailureReason);
        Assert.True(store.Contains("the-key", "victim-nonce"));
    }

    [Fact]
    public async Task SameNonce_DifferentKeyIds_DoNotCollide()
    {
        var keyA = RoundtripTests.CreateFreshKey("ed25519");
        var keyB = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var verifier = Verifier(new StaticKeyResolver().Add("client-a", keyA).Add("client-b", keyB), new InMemoryNonceStore(clock), clock);

        Assert.True((await verifier.VerifyAsync(WithNonce(keyA, "client-a", "shared"))).Succeeded);
        Assert.True((await verifier.VerifyAsync(WithNonce(keyB, "client-b", "shared"))).Succeeded);
        Assert.False((await verifier.VerifyAsync(WithNonce(keyA, "client-a", "shared"))).Succeeded);
    }

    [Fact]
    public async Task NonceIsRemovedFromStoreAfterAcceptanceWindow()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var store = new InMemoryNonceStore(clock);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), store, clock, maxAge: TimeSpan.FromMinutes(5));

        Assert.True((await verifier.VerifyAsync(WithNonce(key, "the-key", "n1"))).Succeeded);

        // Window = created + MaxAge (5 min) + ClockSkew (1 min): still held just before its end.
        clock.Advance(TimeSpan.FromMinutes(6) - TimeSpan.FromSeconds(1));
        store.Prune();
        Assert.True(store.Contains("the-key", "n1"));

        // At the exact end of the window the signature is still acceptable, so the nonce must still be held.
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.False((await verifier.VerifyAsync(WithNonce(key, "the-key", "n1"))).Succeeded);
        Assert.True(store.Contains("the-key", "n1"));

        clock.Advance(TimeSpan.FromSeconds(1));
        store.Prune();
        Assert.False(store.Contains("the-key", "n1"));
        Assert.Equal(0, store.Count);

        // Past the window the signature itself is too old, so a replay is still rejected.
        var replay = await verifier.VerifyAsync(WithNonce(key, "the-key", "n1"));
        Assert.False(replay.Succeeded);
    }

    [Fact]
    public async Task NonceRetention_UsesEarlierExpires()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var clock = new FakeTimeProvider(Now);
        var store = new InMemoryNonceStore(clock);
        var verifier = Verifier(new StaticKeyResolver().Add("the-key", key), store, clock, maxAge: TimeSpan.FromMinutes(30));

        // expires (now + 2 min) + ClockSkew (1 min) ends before created + MaxAge + ClockSkew.
        Assert.True((await verifier.VerifyAsync(SignedMessage(key, lifetime: TimeSpan.FromMinutes(2)))).Succeeded);
        Assert.Equal(1, store.Count);

        clock.Advance(TimeSpan.FromMinutes(3));
        store.Prune();
        Assert.Equal(1, store.Count);

        clock.Advance(TimeSpan.FromSeconds(1));
        store.Prune();
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public async Task InMemoryNonceStore_AllowsReuseAfterExpiry()
    {
        var clock = new FakeTimeProvider(Now);
        var store = new InMemoryNonceStore(clock);

        Assert.True(await store.TryAddAsync("k", "n1", Now.AddMinutes(5)));
        Assert.False(await store.TryAddAsync("k", "n1", Now.AddMinutes(5)));
        Assert.True(await store.TryAddAsync("other", "n1", Now.AddMinutes(5)));

        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.True(await store.TryAddAsync("k", "n1", clock.GetUtcNow().AddMinutes(5)));
    }

    [Fact]
    public async Task Middleware_RejectsReplayedRequest()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        using var host = await new HostBuilder()
            .ConfigureWebHost(webHost => webHost
                .UseTestServer()
                .ConfigureServices(services => services.AddHttpMessageSignatureVerification(options =>
                {
                    options.KeyResolver = new StaticKeyResolver().Add("client", key);
                    options.NonceStore = new InMemoryNonceStore();
                    options.RequireNonce = true;
                }))
                .Configure(app =>
                {
                    app.UseHttpMessageSignatureVerification();
                    app.Run(context => context.Response.WriteAsync("ok"));
                }))
            .StartAsync();

        var signer = new HttpMessageSigner(key)
        {
            KeyId = "client",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            NonceLength = 16,
        };

        using var client = host.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "http://localhost/resource");
        var signed = signer.Sign(new HttpRequestMessageContext(request));

        HttpRequestMessage Copy()
        {
            var copy = new HttpRequestMessage(HttpMethod.Get, "http://localhost/resource");
            copy.Headers.TryAddWithoutValidation("Signature-Input", signed.SignatureInput);
            copy.Headers.TryAddWithoutValidation("Signature", signed.Signature);
            return copy;
        }

        using var first = await client.SendAsync(Copy());
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);

        using var replay = await client.SendAsync(Copy());
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);

        // A request signed without a nonce is rejected when RequireNonce is set.
        var noNonce = new HttpMessageSigner(key)
        {
            KeyId = "client",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        };
        using var withoutNonce = new HttpRequestMessage(HttpMethod.Get, "http://localhost/resource");
        noNonce.Sign(withoutNonce);
        using var rejected = await client.SendAsync(withoutNonce);
        Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);

        await host.StopAsync();
    }
}
