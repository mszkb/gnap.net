using System.Security.Cryptography;
using System.Text;
using Gnap.Core.Keys;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Gnap.Core.Tests;

public class HttpSigProofingTests
{
    private const string RequestBody = /*lang=json,strict*/ """{"access_token":{"access":["dolphin-metadata"]}}""";

    private static (JsonWebKey PrivateJwk, JsonWebKey PublicJwk) CreateKeyPair()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateJwk = JsonWebKey.FromECDsa(key, includePrivateKey: true, keyId: "test-key");
        return (privateJwk, privateJwk.ToPublicKey());
    }

    private static HttpRequestMessage CreateRequest(string? body = RequestBody)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://server.example.com/gnap");
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return request;
    }

    private static KeyProofContext CreateContext(HttpRequestMessage request, JsonWebKey publicJwk, string? body = RequestBody) => new()
    {
        Message = new HttpRequestMessageContext(request),
        Key = publicJwk.ToSignatureAlgorithm(),
        Content = body is null ? null : Encoding.UTF8.GetBytes(body),
    };

    [Fact]
    public async Task SignedRequest_Validates()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        // The proofer added the required headers.
        Assert.True(request.Headers.Contains("Signature"));
        Assert.True(request.Headers.Contains("Signature-Input"));
        Assert.True(request.Content!.Headers.Contains("Content-Digest"));

        var result = await new HttpSigKeyProofValidator().ValidateAsync(CreateContext(request, publicJwk));
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task RequestWithoutContent_Validates()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://rs.example.com/resource");
        request.Headers.TryAddWithoutValidation("Authorization", "GNAP 80UPRY5NM33OMUKMKSKU");
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        var result = await new HttpSigKeyProofValidator().ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = publicJwk.ToSignatureAlgorithm(),
        });
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task WrongKey_IsRejected()
    {
        var (privateJwk, _) = CreateKeyPair();
        var (_, otherPublicJwk) = CreateKeyPair();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        var result = await new HttpSigKeyProofValidator().ValidateAsync(CreateContext(request, otherPublicJwk));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task TamperedBody_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        var tampered = /*lang=json,strict*/ """{"access_token":{"access":["all-the-dolphins"]}}""";
        var result = await new HttpSigKeyProofValidator().ValidateAsync(CreateContext(request, publicJwk, tampered));
        Assert.False(result.Succeeded);
        Assert.Contains("Content-Digest", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StrippedContentDigest_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);
        request.Content!.Headers.Remove("Content-Digest");

        var result = await new HttpSigKeyProofValidator().ValidateAsync(CreateContext(request, publicJwk));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task ReplayedNonce_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        var validator = new HttpSigKeyProofValidator { NonceStore = new InMemoryNonceStore() };
        var first = await validator.ValidateAsync(CreateContext(request, publicJwk));
        Assert.True(first.Succeeded, first.FailureReason);

        var replay = await validator.ValidateAsync(CreateContext(request, publicJwk));
        Assert.False(replay.Succeeded);
        Assert.Contains("replay", replay.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MissingGnapTag_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest(body: null);

        // Sign correctly per RFC 9421 but without the GNAP tag parameter.
        var signer = new HttpMessageSigner(privateJwk.ToSignatureAlgorithm())
        {
            KeyId = "test-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            NonceLength = 16,
        };
        signer.Sign(request);

        var result = await new HttpSigKeyProofValidator().ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = publicJwk.ToSignatureAlgorithm(),
        });
        Assert.False(result.Succeeded);
        Assert.Contains("tag", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AdvertisedAlgParameter_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest(body: null);

        var signer = new HttpMessageSigner(privateJwk.ToSignatureAlgorithm())
        {
            KeyId = "test-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            IncludeAlgorithm = true,
            Tag = "gnap",
        };
        signer.Sign(request);

        var result = await new HttpSigKeyProofValidator().ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = publicJwk.ToSignatureAlgorithm(),
        });
        Assert.False(result.Succeeded);
        Assert.Contains("alg", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task StaleSignature_IsRejected()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        var request = CreateRequest();
        var proofer = new HttpSigKeyProofer(privateJwk.ToSignatureAlgorithm(), "test-key") { TimeProvider = clock };
        await proofer.AddProofAsync(request);

        clock.Advance(TimeSpan.FromMinutes(20));
        var validator = new HttpSigKeyProofValidator { TimeProvider = clock };
        var result = await validator.ValidateAsync(CreateContext(request, publicJwk));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task MissingNonce_IsRejected_WhenRequired()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest(body: null);

        var signer = new HttpMessageSigner(privateJwk.ToSignatureAlgorithm())
        {
            KeyId = "test-key",
            CoveredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri],
            Tag = "gnap",
        };
        signer.Sign(request);

        var validator = new HttpSigKeyProofValidator { RequireNonce = true };
        var result = await validator.ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = publicJwk.ToSignatureAlgorithm(),
        });
        Assert.False(result.Succeeded);
        Assert.Contains("nonce", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task KeyIdMismatch_IsRejected_WhenExpectedKeyIdSet()
    {
        var (privateJwk, publicJwk) = CreateKeyPair();
        var request = CreateRequest();
        var proofer = new HttpSigKeyProofer(privateJwk.ToSignatureAlgorithm(), keyId: "some-other-key");
        await proofer.AddProofAsync(request);

        var validator = new HttpSigKeyProofValidator { ExpectedKeyId = "test-key" };
        var result = await validator.ValidateAsync(CreateContext(request, publicJwk));
        Assert.False(result.Succeeded);
        Assert.Contains("keyid", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnsignedRequest_IsRejected()
    {
        var (_, publicJwk) = CreateKeyPair();
        var request = CreateRequest(body: null);

        var result = await new HttpSigKeyProofValidator().ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = publicJwk.ToSignatureAlgorithm(),
        });
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task Ed25519Proof_Validates()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        var publicKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(privateKey)
            .GeneratePublicKey().GetEncoded();
        var privateJwk = JsonWebKey.FromEd25519(publicKey, privateKey, keyId: "ed-key");

        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);

        var result = await new HttpSigKeyProofValidator { ExpectedKeyId = "ed-key" }
            .ValidateAsync(CreateContext(request, privateJwk.ToPublicKey()));
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task NonceStore_AllowsReuseAfterExpiry()
    {
        var clock = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T12:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var store = new InMemoryNonceStore(clock);

        Assert.True(await store.TryRegisterAsync("n1", clock.GetUtcNow().AddMinutes(5)));
        Assert.False(await store.TryRegisterAsync("n1", clock.GetUtcNow().AddMinutes(5)));

        clock.Advance(TimeSpan.FromMinutes(6));
        Assert.True(await store.TryRegisterAsync("n1", clock.GetUtcNow().AddMinutes(5)));
    }
}
