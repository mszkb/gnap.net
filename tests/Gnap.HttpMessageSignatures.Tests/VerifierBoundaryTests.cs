using System.Text;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>
/// Timestamp window boundaries, malformed signature fields and nonce retention of
/// <see cref="HttpMessageVerifier"/>. Pins exact boundary behaviour so off-by-one
/// mutations are detected (Stryker.NET, see docs/mutation-testing.md).
/// </summary>
public class VerifierBoundaryTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 9, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Skew = TimeSpan.FromMinutes(1);

    private sealed class RecordingNonceStore : INonceStore
    {
        public List<(string KeyId, string Nonce, DateTimeOffset ExpiresAt)> Entries { get; } = [];

        public ValueTask<bool> TryAddAsync(string keyId, string nonce, DateTimeOffset expiresAt, CancellationToken cancellationToken = default)
        {
            Entries.Add((keyId, nonce, expiresAt));
            return ValueTask.FromResult(true);
        }
    }

    private static SimpleHttpMessage Signed(
        SignatureAlgorithm key,
        DateTimeOffset? created,
        DateTimeOffset? expires = null,
        string? nonce = null,
        string? keyId = "the-key")
    {
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Method);
        parameters = created is { } c ? parameters.WithCreated(c) : parameters;
        parameters = expires is { } e ? parameters.WithExpires(e) : parameters;
        parameters = keyId is not null ? parameters.WithKeyId(keyId) : parameters;
        parameters = nonce is not null ? parameters.WithNonce(nonce) : parameters;
        var message = SimpleHttpMessage.Request("GET", "https://example.com/");
        var signature = key.Sign(Encoding.UTF8.GetBytes(SignatureBaseBuilder.Build(message, parameters)));
        message.WithHeader("Signature-Input", $"sig1={parameters.Serialize()}");
        message.WithHeader("Signature", $"sig1=:{Convert.ToBase64String(signature)}:");
        return message;
    }

    private static HttpMessageVerifier Verifier(
        SignatureAlgorithm key,
        TimeSpan? maxAge = null,
        INonceStore? nonceStore = null,
        bool requireCreated = true) =>
        new(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("the-key", key),
            TimeProvider = new FakeTimeProvider(Now),
            ClockSkew = Skew,
            MaxAge = maxAge,
            NonceStore = nonceStore,
            RequireCreated = requireCreated,
            NonceRetention = TimeSpan.FromMinutes(7),
        });

    [Fact]
    public async Task CreatedExactlyAtFutureSkewLimit_IsAccepted()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key).VerifyAsync(Signed(key, created: Now + Skew));

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task CreatedOneSecondBeyondFutureSkewLimit_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key).VerifyAsync(Signed(key, created: Now + Skew + TimeSpan.FromSeconds(1)));

        Assert.False(result.Succeeded);
        Assert.Equal("Signature 'sig1': The signature's created time lies in the future.", result.FailureReason);
    }

    [Fact]
    public async Task CreatedExactlyAtMaxAgeLimit_IsAccepted()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var maxAge = TimeSpan.FromMinutes(5);

        var result = await Verifier(key, maxAge).VerifyAsync(Signed(key, created: Now - maxAge - Skew));

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task CreatedOneSecondBeyondMaxAgeLimit_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var maxAge = TimeSpan.FromMinutes(5);

        var result = await Verifier(key, maxAge).VerifyAsync(Signed(key, created: Now - maxAge - Skew - TimeSpan.FromSeconds(1)));

        Assert.False(result.Succeeded);
        Assert.Equal("Signature 'sig1': The signature is older than the allowed maximum age.", result.FailureReason);
    }

    [Fact]
    public async Task ExpiresExactlyAtSkewLimit_IsAccepted()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key).VerifyAsync(Signed(key, created: Now, expires: Now - Skew));

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task ExpiresOneSecondBeyondSkewLimit_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key).VerifyAsync(Signed(key, created: Now, expires: Now - Skew - TimeSpan.FromSeconds(1)));

        Assert.False(result.Succeeded);
        Assert.Equal("Signature 'sig1': The signature has expired.", result.FailureReason);
    }

    [Fact]
    public async Task MissingCreated_IsAcceptedWhenNotRequired()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key, requireCreated: false).VerifyAsync(Signed(key, created: null));

        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task SignatureInputMemberThatIsNotAnInnerList_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var message = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("Signature-Input", "sig1=\"@method\"")
            .WithHeader("Signature", "sig1=:AAAA:");

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Equal("Signature 'sig1': The Signature-Input member is not an inner list.", result.FailureReason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("sig1=\"not bytes\"")]
    [InlineData("other=:AAAA:")]
    public async Task SignatureWithoutMatchingByteSequence_IsRejected(string? signatureHeader)
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var signed = Signed(key, created: Now);
        var message = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("Signature-Input", signed.GetFieldValues("signature-input")[0]);
        if (signatureHeader is not null)
        {
            message.WithHeader("Signature", signatureHeader);
        }

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Equal("Signature 'sig1': No matching byte-sequence member in the Signature field.", result.FailureReason);
    }

    [Fact]
    public async Task MalformedSignatureField_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var message = SimpleHttpMessage.Request("GET", "https://example.com/")
            .WithHeader("Signature-Input", "sig1=(\"@method\");created=1")
            .WithHeader("Signature", "sig1=:AAAA");

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.StartsWith("Malformed signature fields: ", result.FailureReason, StringComparison.Ordinal);
        Assert.Empty(result.Signatures);
    }

    [Fact]
    public async Task UnknownLabel_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(key).VerifyAsync(Signed(key, created: Now), label: "other");

        Assert.False(result.Succeeded);
        Assert.Equal("The message carries no signature labeled 'other'.", result.FailureReason);
    }

    [Fact]
    public async Task NonceWithoutBoundedWindow_IsRetainedForNonceRetention()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var store = new RecordingNonceStore();

        var result = await Verifier(key, nonceStore: store).VerifyAsync(Signed(key, created: Now, nonce: "n1"));

        Assert.True(result.Succeeded, result.FailureReason);
        var entry = Assert.Single(store.Entries);
        Assert.Equal(("the-key", "n1", Now + TimeSpan.FromMinutes(7)), entry);
    }

    [Fact]
    public async Task NonceWithMaxAge_IsRetainedOneTickPastWindowEnd()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var store = new RecordingNonceStore();
        var created = Now - TimeSpan.FromMinutes(2);

        var result = await Verifier(key, maxAge: TimeSpan.FromMinutes(5), nonceStore: store)
            .VerifyAsync(Signed(key, created: created, nonce: "n1"));

        Assert.True(result.Succeeded, result.FailureReason);
        Assert.Equal(created + TimeSpan.FromMinutes(5) + Skew + TimeSpan.FromTicks(1), Assert.Single(store.Entries).ExpiresAt);
    }

    [Theory]
    [InlineData(3, 3)] // expires + skew ends first
    [InlineData(30, 6)] // created + MaxAge + skew ends first
    public async Task NonceWithMaxAgeAndExpires_IsRetainedUntilEarlierWindowEnd(int expiresInMinutes, int expectedMinutes)
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var store = new RecordingNonceStore();

        var result = await Verifier(key, maxAge: TimeSpan.FromMinutes(5), nonceStore: store)
            .VerifyAsync(Signed(key, created: Now, expires: Now + TimeSpan.FromMinutes(expiresInMinutes - 1), nonce: "n1"));

        Assert.True(result.Succeeded, result.FailureReason);
        Assert.Equal(Now + TimeSpan.FromMinutes(expectedMinutes) + TimeSpan.FromTicks(1), Assert.Single(store.Entries).ExpiresAt);
    }

    [Fact]
    public async Task NonceWithoutKeyId_IsScopedToEmptyKeyId()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var store = new RecordingNonceStore();
        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new SingleKeyResolver(key),
            TimeProvider = new FakeTimeProvider(Now),
            NonceStore = store,
        });

        var result = await verifier.VerifyAsync(Signed(key, created: Now, nonce: "n1", keyId: null));

        Assert.True(result.Succeeded, result.FailureReason);
        Assert.Equal(string.Empty, Assert.Single(store.Entries).KeyId);
    }

    private sealed class SingleKeyResolver(SignatureAlgorithm key) : IVerificationKeyResolver
    {
        public ValueTask<SignatureAlgorithm?> ResolveAsync(string? keyId, string? algorithm, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<SignatureAlgorithm?>(key);
    }
}
