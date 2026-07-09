using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Gnap.HttpMessageSignatures.Tests;

/// <summary>Security-relevant failure paths of the verifier and base builder.</summary>
public class NegativeVerificationTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 9, 12, 0, 0, TimeSpan.Zero);

    private static (SimpleHttpMessage Message, SignatureAlgorithm Key) SignedMessage(
        Action<FakeTimeProvider>? adjustSigningClock = null,
        TimeSpan? lifetime = null)
    {
        var clock = new FakeTimeProvider(Now);
        adjustSigningClock?.Invoke(clock);
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var signer = new HttpMessageSigner(key)
        {
            KeyId = "the-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.Field("date")],
            Lifetime = lifetime,
            TimeProvider = clock,
        };
        var message = SimpleHttpMessage.Request("POST", "https://example.com/api")
            .WithHeader("Date", Now.ToString("r"));
        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);
        return (message, key);
    }

    private static HttpMessageVerifier Verifier(SignatureAlgorithm key, Action<FakeTimeProvider>? adjustClock = null, TimeSpan? maxAge = null)
    {
        var clock = new FakeTimeProvider(Now);
        adjustClock?.Invoke(clock);
        return new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("the-key", key),
            TimeProvider = clock,
            MaxAge = maxAge,
        });
    }

    [Fact]
    public async Task TamperedCoveredHeader_IsRejected()
    {
        var (message, key) = SignedMessage();
        var tampered = SimpleHttpMessage.Request("POST", "https://example.com/api")
            .WithHeader("Date", Now.AddMinutes(1).ToString("r"));
        foreach (var header in message.GetFieldValues("signature-input"))
        {
            tampered.WithHeader("Signature-Input", header);
        }

        foreach (var header in message.GetFieldValues("signature"))
        {
            tampered.WithHeader("Signature", header);
        }

        var result = await Verifier(key).VerifyAsync(tampered);

        Assert.False(result.Succeeded);
        Assert.Contains("does not match the signature base", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExpiredSignature_IsRejected()
    {
        var (message, key) = SignedMessage(lifetime: TimeSpan.FromMinutes(1));

        var result = await Verifier(key, clock => clock.Advance(TimeSpan.FromMinutes(30))).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("expired", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CreatedInTheFuture_IsRejected()
    {
        var (message, key) = SignedMessage(clock => clock.Advance(TimeSpan.FromHours(2)));

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("future", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SignatureOlderThanMaxAge_IsRejected()
    {
        var (message, key) = SignedMessage();

        var result = await Verifier(
            key,
            clock => clock.Advance(TimeSpan.FromHours(1)),
            maxAge: TimeSpan.FromMinutes(10)).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("maximum age", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownKeyId_IsRejected()
    {
        var (message, _) = SignedMessage();
        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver(),
            TimeProvider = new FakeTimeProvider(Now),
        });

        var result = await verifier.VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("Unknown key", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WrongKeyForKeyId_IsRejected()
    {
        var (message, _) = SignedMessage();
        var otherKey = RoundtripTests.CreateFreshKey("ed25519");

        var result = await Verifier(otherKey).VerifyAsync(message);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task AlgorithmParameterMismatch_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var signer = new HttpMessageSigner(key)
        {
            KeyId = "the-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            IncludeAlgorithm = true,
            TimeProvider = new FakeTimeProvider(Now),
        };
        var message = SimpleHttpMessage.Request("GET", "https://example.com/");
        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput.Replace("alg=\"ed25519\"", "alg=\"hmac-sha256\""));
        message.WithHeader("Signature", signed.Signature);

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("does not match the key's algorithm", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingCoveredField_IsRejected()
    {
        var (message, key) = SignedMessage();
        var withoutDate = SimpleHttpMessage.Request("POST", "https://example.com/api");
        foreach (var header in message.GetFieldValues("signature-input"))
        {
            withoutDate.WithHeader("Signature-Input", header);
        }

        foreach (var header in message.GetFieldValues("signature"))
        {
            withoutDate.WithHeader("Signature", header);
        }

        var result = await Verifier(key).VerifyAsync(withoutDate);

        Assert.False(result.Succeeded);
        Assert.Contains("'date' is not present", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingSignatureField_IsRejected()
    {
        var (message, key) = SignedMessage();
        var incomplete = SimpleHttpMessage.Request("POST", "https://example.com/api")
            .WithHeader("Date", Now.ToString("r"));
        foreach (var header in message.GetFieldValues("signature-input"))
        {
            incomplete.WithHeader("Signature-Input", header);
        }

        var result = await Verifier(key).VerifyAsync(incomplete);

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task UnsignedMessage_IsRejected()
    {
        var result = await Verifier(RoundtripTests.CreateFreshKey("ed25519"))
            .VerifyAsync(SimpleHttpMessage.Request("GET", "https://example.com/"));

        Assert.False(result.Succeeded);
        Assert.Contains("no Signature-Input", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingRequiredComponent_IsRejected()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var signer = new HttpMessageSigner(key)
        {
            KeyId = "the-key",
            CoveredComponents = [SignatureComponent.Method],
        };
        var message = SimpleHttpMessage.Request("GET", "https://example.com/");
        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);

        var verifier = new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add("the-key", key),
            RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
        });
        var result = await verifier.VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("required component", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SignatureWithoutCreated_IsRejectedByDefault()
    {
        var key = RoundtripTests.CreateFreshKey("ed25519");
        var signer = new HttpMessageSigner(key)
        {
            KeyId = "the-key",
            CoveredComponents = [SignatureComponent.Method],
            IncludeCreated = false,
        };
        var message = SimpleHttpMessage.Request("GET", "https://example.com/");
        var signed = signer.Sign(message);
        message.WithHeader("Signature-Input", signed.SignatureInput);
        message.WithHeader("Signature", signed.Signature);

        var result = await Verifier(key).VerifyAsync(message);

        Assert.False(result.Succeeded);
        Assert.Contains("no created parameter", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public void DuplicateCoveredComponent_ThrowsWhenBuilding()
    {
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Method);

        Assert.Throws<HttpMessageSignatureException>(() => parameters.AddComponent(SignatureComponent.Method));
    }

    [Fact]
    public void CoveringSignatureParams_Throws()
    {
        var parameters = new SignatureParameters();

        Assert.Throws<HttpMessageSignatureException>(() => parameters.AddComponent(SignatureComponent.Derived("@signature-params")));
    }

    [Fact]
    public void StatusOnRequest_Throws()
    {
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Status);

        Assert.Throws<HttpMessageSignatureException>(
            () => SignatureBaseBuilder.Build(SimpleHttpMessage.Request("GET", "https://example.com/"), parameters));
    }

    [Fact]
    public void ReqFlagOnRequest_Throws()
    {
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.Method.WithRequest());

        Assert.Throws<HttpMessageSignatureException>(
            () => SignatureBaseBuilder.Build(SimpleHttpMessage.Request("GET", "https://example.com/"), parameters));
    }

    [Fact]
    public void BsCombinedWithSf_Throws()
    {
        var parameters = new SignatureParameters().AddComponent(
            SignatureComponent.Field("date").WithByteSequenceEncoding().WithStructuredFieldSerialization());
        var message = SimpleHttpMessage.Request("GET", "https://example.com/").WithHeader("Date", "x");

        Assert.Throws<HttpMessageSignatureException>(() => SignatureBaseBuilder.Build(message, parameters));
    }

    [Fact]
    public void MissingQueryParam_Throws()
    {
        var parameters = new SignatureParameters().AddComponent(SignatureComponent.QueryParam("missing"));

        Assert.Throws<HttpMessageSignatureException>(
            () => SignatureBaseBuilder.Build(SimpleHttpMessage.Request("GET", "https://example.com/?other=1"), parameters));
    }
}
