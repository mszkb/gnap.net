using System.Security.Cryptography;
using System.Text;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;
using Xunit;

namespace Gnap.Core.Tests;

/// <summary>
/// Covers the remaining key-proof manipulation classes (signed components swapped
/// after signing) and the object form of the <c>httpsig</c> proof method with its
/// <c>alg</c> and <c>content-digest-alg</c> parameters (RFC 9635 Section 7.3.1).
/// </summary>
public class HttpSigProofParameterTests
{
    private const string Body = /*lang=json,strict*/ """{"access_token":{"access":["dolphin-metadata"]}}""";

    private static JsonWebKey CreatePrivateJwk()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return JsonWebKey.FromECDsa(key, includePrivateKey: true, keyId: "param-key");
    }

    private static HttpRequestMessage CreateRequest(string? body = Body)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://server.example.com/gnap");
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return request;
    }

    private static KeyProofContext Context(HttpRequestMessage request, SignatureAlgorithm key, string? body = Body) => new()
    {
        Message = new HttpRequestMessageContext(request),
        Key = key,
        Content = body is null ? null : Encoding.UTF8.GetBytes(body),
    };

    [Fact]
    public async Task TamperedTargetUri_IsRejected()
    {
        var jwk = CreatePrivateJwk();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);
        request.RequestUri = new Uri("https://evil.example.com/gnap");

        var result = await new HttpSigKeyProofValidator().ValidateAsync(Context(request, jwk.ToPublicKey().ToSignatureAlgorithm()));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task TamperedMethod_IsRejected()
    {
        var jwk = CreatePrivateJwk();
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);
        request.Method = HttpMethod.Put;

        var result = await new HttpSigKeyProofValidator().ValidateAsync(Context(request, jwk.ToPublicKey().ToSignatureAlgorithm()));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task SwappedAccessToken_IsRejected()
    {
        var jwk = CreatePrivateJwk();
        var request = CreateRequest(body: null);
        GnapAuthorization.Apply(request, "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0");
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);
        GnapAuthorization.Apply(request, "STOLEN-TOKEN-VALUE");

        var result = await new HttpSigKeyProofValidator().ValidateAsync(Context(request, jwk.ToPublicKey().ToSignatureAlgorithm(), body: null));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task AuthorizationAddedAfterSigning_IsRejected()
    {
        var jwk = CreatePrivateJwk();
        var request = CreateRequest(body: null);
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);
        GnapAuthorization.Apply(request, "SMUGGLED-TOKEN");

        var result = await new HttpSigKeyProofValidator().ValidateAsync(Context(request, jwk.ToPublicKey().ToSignatureAlgorithm(), body: null));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public void ProofMethod_ForHttpSig_SerializesObjectForm()
    {
        var key = GnapKey.ForHttpSig(CreatePrivateJwk(), ContentDigestAlgorithm.Sha512);
        var request = new GrantRequest { Client = new ClientInstance { Key = key } };

        var parsed = GnapJson.DeserializeGrantRequest(GnapJson.Serialize(request))!;
        var proof = parsed.Client!.Key!.Proof!;
        Assert.Equal(ProofMethod.Methods.HttpSig, proof.Method);
        Assert.Equal("ecdsa-p256-sha256", proof.HttpSigAlgorithm);
        Assert.Equal(ContentDigestAlgorithm.Sha512, proof.GetContentDigestAlgorithm());
        Assert.False(parsed.Client.Key.Jwk!.HasPrivateKey);
    }

    [Fact]
    public void StringFormProof_PinsNothing()
    {
        var proof = new ProofMethod(ProofMethod.Methods.HttpSig);
        Assert.Null(proof.HttpSigAlgorithm);
        Assert.Null(proof.GetContentDigestAlgorithm());
    }

    [Fact]
    public void UnsupportedContentDigestAlg_Throws()
    {
        var proof = GnapJson.DeserializeGrantRequest(/*lang=json,strict*/ """
            {"client":{"key":{"proof":{"method":"httpsig","alg":"ed25519","content-digest-alg":"md5"},"jwk":{"kty":"OKP","crv":"Ed25519","x":"AA"}}}}
            """)!.Client!.Key!.Proof!;
        Assert.Throws<GnapException>(() => proof.GetContentDigestAlgorithm());
    }

    [Fact]
    public void PinnedAlg_MismatchingKey_IsRejected()
    {
        var key = new GnapKey
        {
            Proof = ProofMethod.ForHttpSig("ed25519"),
            Jwk = CreatePrivateJwk().ToPublicKey(),
        };

        Assert.Throws<GnapException>(() => key.ToSignatureAlgorithm());
    }

    [Theory]
    [InlineData("rsa-v1_5-sha256", null, "rsa-v1_5-sha256")]
    [InlineData("rsa-pss-sha512", null, "rsa-pss-sha512")]
    [InlineData("rsa-v1_5-sha256", "RS256", "rsa-v1_5-sha256")]
    public void PinnedAlg_SelectsRsaVariant(string pinned, string? jwsAlg, string expected)
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKey.FromRsa(rsa);
        jwk.Alg = jwsAlg;
        var key = new GnapKey { Proof = ProofMethod.ForHttpSig(pinned), Jwk = jwk };

        Assert.Equal(expected, key.ToSignatureAlgorithm().Name);
    }

    [Fact]
    public void PinnedAlg_ConflictingWithJwsAlg_IsRejected()
    {
        using var rsa = RSA.Create(2048);
        var jwk = JsonWebKey.FromRsa(rsa, algorithm: "PS512");
        var key = new GnapKey { Proof = ProofMethod.ForHttpSig("rsa-v1_5-sha256"), Jwk = jwk };

        Assert.Throws<GnapException>(() => key.ToSignatureAlgorithm());
    }

    [Fact]
    public async Task PinnedContentDigestAlg_IsHonoured()
    {
        var jwk = CreatePrivateJwk();
        var proofer = new HttpSigKeyProofer(jwk.ToSignatureAlgorithm(), jwk.Kid) { ContentDigestAlgorithm = ContentDigestAlgorithm.Sha512 };
        var presented = new GnapKey { Proof = proofer.ToProofMethod(), Jwk = jwk.ToPublicKey() };
        var request = CreateRequest();
        await proofer.AddProofAsync(request);

        var result = await HttpSigKeyProofValidator.ForKey(presented).ValidateAsync(Context(request, presented.ToSignatureAlgorithm()));
        Assert.True(result.Succeeded, result.FailureReason);
    }

    [Fact]
    public async Task PinnedContentDigestAlg_WrongDigest_IsRejected()
    {
        var jwk = CreatePrivateJwk();
        var presented = GnapKey.ForHttpSig(jwk, ContentDigestAlgorithm.Sha512);
        var request = CreateRequest();

        // The client signs with the default sha-256 digest despite pinning sha-512.
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);

        var result = await HttpSigKeyProofValidator.ForKey(presented).ValidateAsync(Context(request, presented.ToSignatureAlgorithm()));
        Assert.False(result.Succeeded);
        Assert.Contains("sha-512", result.FailureReason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ForKey_EnforcesKeyId()
    {
        var jwk = CreatePrivateJwk();
        var presented = GnapKey.ForHttpSig(jwk);
        presented.Jwk!.Kid = "a-different-kid";
        var request = CreateRequest();
        await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);

        var result = await HttpSigKeyProofValidator.ForKey(presented).ValidateAsync(Context(request, presented.ToSignatureAlgorithm()));
        Assert.False(result.Succeeded);
    }

    [Fact]
    public void ForKey_RejectsOtherProofMethods()
    {
        var key = new GnapKey { Proof = new ProofMethod(ProofMethod.Methods.Mtls), Jwk = CreatePrivateJwk().ToPublicKey() };
        Assert.Throws<GnapException>(() => HttpSigKeyProofValidator.ForKey(key));
    }
}
