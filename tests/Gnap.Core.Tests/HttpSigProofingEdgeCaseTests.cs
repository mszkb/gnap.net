using System.Security.Cryptography;
using System.Text;
using Gnap.Core.Keys;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;
using Xunit;

namespace Gnap.Core.Tests;

/// <summary>
/// Edge cases of <c>httpsig</c> key proofing: argument validation, the components a GNAP
/// signature must cover, required signature parameters and the exact failure reasons.
/// (These pin behaviour found by mutation testing, see stryker-config.keyproofing.json.)
/// </summary>
public class HttpSigProofingEdgeCaseTests
{
    private const string Body = /*lang=json,strict*/ """{"access_token":{"access":["dolphin-metadata"]}}""";
    private static readonly Uri Target = new("https://server.example.com/gnap");

    private static JsonWebKey NewKey(string kid = "test-key")
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return JsonWebKey.FromECDsa(key, includePrivateKey: true, keyId: kid);
    }

    private static HttpRequestMessage Request(string? body = Body, ContentDigestAlgorithm digest = ContentDigestAlgorithm.Sha256)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Target);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            request.Content.Headers.TryAddWithoutValidation(
                "Content-Digest", ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(body), digest));
        }

        return request;
    }

    /// <summary>Signs like a GNAP client would, but with full control over the covered components.</summary>
    private static void Sign(HttpRequestMessage request, JsonWebKey key, SignatureComponent[] components, bool includeCreated = true) =>
        new HttpMessageSigner(key.ToSignatureAlgorithm())
        {
            KeyId = key.Kid,
            CoveredComponents = components,
            IncludeCreated = includeCreated,
            Tag = GnapConstants.HttpSignatureTag,
            NonceLength = 16,
        }.Sign(request);

    private static Task<KeyProofResult> ValidateAsync(HttpRequestMessage request, JsonWebKey key, string? body = Body, HttpSigKeyProofValidator? validator = null) =>
        (validator ?? new HttpSigKeyProofValidator()).ValidateAsync(new KeyProofContext
        {
            Message = new HttpRequestMessageContext(request),
            Key = key.ToPublicKey().ToSignatureAlgorithm(),
            Content = body is null ? null : Encoding.UTF8.GetBytes(body),
        });

    [Fact]
    public void Constructors_RejectMissingArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new HttpSigKeyProofer(null!));
        Assert.Throws<ArgumentNullException>(() => HttpSigKeyProofer.FromJwk(null!));
        Assert.Throws<ArgumentNullException>(() => HttpSigKeyProofValidator.ForKey(null!));
    }

    [Fact]
    public void Proofer_RejectsVerificationOnlyKeys()
    {
        var publicOnly = SignatureAlgorithm.Ed25519(Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")); // RFC 8032 test 1, public key only
        var e = Assert.Throws<ArgumentException>(() => new HttpSigKeyProofer(publicOnly));
        Assert.Equal("algorithm", e.ParamName);
        Assert.StartsWith("The algorithm has no private key material and cannot create proofs.", e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Proofer_RejectsNullRequest()
    {
        var proofer = HttpSigKeyProofer.FromJwk(NewKey());
        await Assert.ThrowsAsync<ArgumentNullException>(() => proofer.AddProofAsync(null!));
    }

    [Fact]
    public async Task Validator_RejectsNullContext() =>
        await Assert.ThrowsAsync<ArgumentNullException>(() => new HttpSigKeyProofValidator().ValidateAsync(null!));

    [Fact]
    public void ForKey_RejectsOtherProofMethods()
    {
        var key = new GnapKey { Jwk = NewKey().ToPublicKey(), Proof = new ProofMethod("mtls") };
        var e = Assert.Throws<GnapException>(() => HttpSigKeyProofValidator.ForKey(key));
        Assert.Equal("The key uses the proofing method 'mtls', not 'httpsig'.", e.Message);
    }

    [Fact]
    public async Task ContentWithoutDigestField_ReportsTheMissingField()
    {
        var key = NewKey();
        var request = new HttpRequestMessage(HttpMethod.Post, Target) { Content = new StringContent(Body) };
        Sign(request, key, [SignatureComponent.Method, SignatureComponent.TargetUri]);

        var result = await ValidateAsync(request, key);
        Assert.Equal("The message has content but no Content-Digest field.", result.FailureReason);
    }

    [Fact]
    public async Task RequiredDigestAlgorithm_IsFoundAmongSeveralEntries()
    {
        // Content-Digest carries sha-256 and sha-512; the key pins sha-512: accepted.
        var key = NewKey();
        var request = Request();
        request.Content!.Headers.Remove("Content-Digest");
        request.Content.Headers.TryAddWithoutValidation("Content-Digest",
            ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(Body), ContentDigestAlgorithm.Sha256) + ", "
            + ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(Body), ContentDigestAlgorithm.Sha512));
        Sign(request, key, [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest]);

        var validator = new HttpSigKeyProofValidator { RequiredContentDigestAlgorithm = ContentDigestAlgorithm.Sha512 };
        var result = await ValidateAsync(request, key, validator: validator);
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task DigestEntriesInSeparateFieldLines_AreCombined()
    {
        // Two Content-Digest field lines are one field (RFC 9110 §5.3).
        var key = NewKey();
        var request = Request();
        request.Content!.Headers.TryAddWithoutValidation("Content-Digest",
            ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(Body), ContentDigestAlgorithm.Sha512));
        Sign(request, key, [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest]);

        var validator = new HttpSigKeyProofValidator { RequiredContentDigestAlgorithm = ContentDigestAlgorithm.Sha512 };
        var result = await ValidateAsync(request, key, validator: validator);
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task MalformedDigestField_FailsThePinnedAlgorithmCheck()
    {
        var key = NewKey();
        var request = Request();
        request.Content!.Headers.Remove("Content-Digest");
        request.Content.Headers.TryAddWithoutValidation("Content-Digest", "sha-512=:unterminated");
        Sign(request, key, [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest]);

        var validator = new HttpSigKeyProofValidator { RequiredContentDigestAlgorithm = ContentDigestAlgorithm.Sha512 };
        var result = await ValidateAsync(request, key, validator: validator);
        Assert.Equal("The Content-Digest field has no 'sha-512' entry required by the key's proof method.", result.FailureReason);
    }

    [Theory]
    [InlineData(0, "@method")]
    [InlineData(1, "@target-uri")]
    [InlineData(2, "content-digest")]
    public async Task SignatureMissingAMandatoryComponent_IsRejected(int omittedIndex, string omitted)
    {
        var key = NewKey();
        var request = Request();
        SignatureComponent[] all = [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest];
        Sign(request, key, all.Where((_, i) => i != omittedIndex).ToArray());

        var result = await ValidateAsync(request, key);
        Assert.False(result.Succeeded);
        Assert.Contains(omitted, result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SignatureWithoutCreated_IsRejected()
    {
        var key = NewKey();
        var request = Request();
        Sign(request, key, [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest], includeCreated: false);

        var result = await ValidateAsync(request, key);
        Assert.False(result.Succeeded);
        Assert.Contains("created", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnsignedMessage_ReportsMissingSignature()
    {
        var result = await ValidateAsync(Request(), NewKey());
        Assert.Equal("The message carries no HTTP message signature.", result.FailureReason);
    }

    [Fact]
    public async Task MalformedSignatureInput_IsReportedAsSuch()
    {
        var request = Request();
        request.Headers.TryAddWithoutValidation("Signature-Input", "sig1=(\"@method\"");
        request.Headers.TryAddWithoutValidation("Signature", "sig1=:AAAA:");

        var result = await ValidateAsync(request, NewKey());
        Assert.False(result.Succeeded);
        Assert.StartsWith("Malformed Signature-Input field: ", result.FailureReason, StringComparison.Ordinal);
    }
}
