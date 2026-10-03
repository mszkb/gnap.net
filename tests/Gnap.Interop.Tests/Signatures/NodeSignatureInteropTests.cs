using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;

namespace Gnap.Interop.Tests.Signatures;

/// <summary>
/// Cross-implementation HTTP Message Signature verification (RFC 9421 / RFC 9530)
/// between our signer/verifier and two JavaScript implementations — the generic
/// <c>http-message-signatures</c> library and Rafiki's
/// <c>@interledger/http-signature-utils</c> — through
/// <c>interop/signatures/crosscheck.mjs</c>. Enabled by
/// <c>GNAP_INTEROP_NODE_SIGNATURES</c> (any value) after <c>npm ci</c> in
/// <c>interop/signatures</c>.
/// </summary>
public sealed class NodeSignatureInteropTests
{
    private const string Enable = "GNAP_INTEROP_NODE_SIGNATURES";

    public static TheoryData<string, string, bool> OurSignatureCases => new()
    {
        // alg, content digest, with Authorization header
        { "ed25519", "sha-256", false },
        { "ed25519", "sha-512", true },
        { "ecdsa-p256-sha256", "sha-256", true },
        { "ecdsa-p256-sha256", "sha-512", false },
    };

    [InteropTheory(Enable)]
    [MemberData(nameof(OurSignatureCases))]
    public async Task Our_GNAP_signatures_verify_in_the_JavaScript_implementations(string alg, string digest, bool withAuthorization)
    {
        var jwk = alg == "ed25519" ? TestKeys.NewEd25519("dotnet-ed25519") : TestKeys.NewP256("dotnet-p256");
        var proofer = new HttpSigKeyProofer(jwk.ToSignatureAlgorithm(), jwk.Kid)
        {
            ContentDigestAlgorithm = digest == "sha-512" ? ContentDigestAlgorithm.Sha512 : ContentDigestAlgorithm.Sha256,
        };

        // Query encoding edge cases: percent-encoded space, reserved characters, an empty value.
        const string body = """{"access_token":{"access":["read"]},"note":"a+b & <c> ü"}""";
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://as.example/gnap/tx?x=a%20b&y=%2F%3F&z=");
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        if (withAuthorization)
        {
            request.Headers.TryAddWithoutValidation("Authorization", "GNAP 80UPRY5NM33OMUKMKSKU");
        }

        await proofer.AddProofAsync(request);

        var headers = new JsonObject();
        foreach (var header in request.Headers.Concat(request.Content.Headers))
        {
            headers[header.Key] = string.Join(", ", header.Value);
        }

        headers["Content-Length"] = Encoding.UTF8.GetByteCount(body).ToString(System.Globalization.CultureInfo.InvariantCulture);

        var result = await RunNodeAsync("verify", new JsonObject
        {
            ["alg"] = alg,
            ["jwk"] = JsonNode.Parse(JsonSerializer.Serialize(jwk.ToPublicKey(), GnapJsonContext.Default.JsonWebKey)),
            ["request"] = new JsonObject
            {
                ["method"] = "POST",
                ["url"] = request.RequestUri!.OriginalString,
                ["headers"] = headers,
                ["body"] = body,
            },
        });

        Assert.True(result["library"]!.GetValue<bool>(), $"http-message-signatures rejected our {alg} signature");
        Assert.True(result["digest"]!.GetValue<bool>(), "Content-Digest mismatch");
        if (alg == "ed25519")
        {
            Assert.True(result["rafiki"]!.GetValue<bool>(), "@interledger/http-signature-utils rejected our signature");
        }
    }

    [InteropTheory(Enable)]
    [InlineData("ed25519", "sha-256")]
    [InlineData("ed25519", "sha-512")]
    [InlineData("ecdsa-p256-sha256", "sha-256")]
    [InlineData("ecdsa-p256-sha256", "sha-512")]
    public async Task JavaScript_signatures_verify_with_our_verifier_and_GNAP_proof_validator(string alg, string digest)
    {
        const string body = """{"interact_ref":"4IFWWIKYBC2PQ6U56NL1"}""";
        var signed = await RunNodeAsync("sign", new JsonObject
        {
            ["alg"] = alg,
            ["digest"] = digest,
            ["request"] = new JsonObject
            {
                ["method"] = "POST",
                ["url"] = "https://as.example/continue/80UPRY5NM33OMUKMKSKU?q=a%20b",
                // Mixed header casing on purpose: field names are case-insensitive.
                ["headers"] = new JsonObject { ["CONTENT-type"] = "application/json", ["Authorization"] = "GNAP 33OMUKMKSKU80UPRY5NM" },
                ["body"] = body,
            },
        });

        var jwk = JsonSerializer.Deserialize(signed["jwk"]!.ToJsonString(), GnapJsonContext.Default.JsonWebKey)!;
        var key = jwk.ToSignatureAlgorithm();

        // The generic library signs with tag="gnap" and a nonce: a complete GNAP proof.
        var library = ToMessage(signed["library"]!);
        Assert.True((await Verify(library, key)).Succeeded);
        var proof = await new HttpSigKeyProofValidator { ExpectedKeyId = jwk.Kid, RequireNonce = true }
            .ValidateAsync(new KeyProofContext { Message = library, Key = key, Content = Encoding.UTF8.GetBytes(body) });
        Assert.True(proof.Succeeded, proof.FailureReason);

        if (alg == "ed25519")
        {
            // Rafiki signs RFC 9421-correctly, but without the tag="gnap" parameter
            // RFC 9635 Section 7.3.1 requires: RFC 9421 verification succeeds, the GNAP
            // proof validator rejects it (documented deviation, docs/interop.md).
            var rafiki = ToMessage(signed["rafiki"]!);
            var verification = await Verify(rafiki, key);
            Assert.True(verification.Succeeded, verification.FailureReason);
            var rafikiProof = await new HttpSigKeyProofValidator { ExpectedKeyId = jwk.Kid }
                .ValidateAsync(new KeyProofContext { Message = rafiki, Key = key, Content = Encoding.UTF8.GetBytes(body) });
            Assert.False(rafikiProof.Succeeded);
            Assert.Contains("tag", rafikiProof.FailureReason, StringComparison.Ordinal);
        }
    }

    private static Task<VerificationResult> Verify(SimpleHttpMessage message, SignatureAlgorithm key) =>
        new HttpMessageVerifier(new VerificationOptions
        {
            KeyResolver = new StaticKeyResolver().Add(key.Name, key).Add("node-ed25519", key).Add("node-ecdsa-p256-sha256", key),
            RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri, SignatureComponent.ContentDigest, SignatureComponent.Field("authorization")],
        }).VerifyAsync(message, "sig1");

    private static SimpleHttpMessage ToMessage(JsonNode request)
    {
        var message = SimpleHttpMessage.Request(request["method"]!.GetValue<string>(), request["url"]!.GetValue<string>());
        foreach (var (name, value) in request["headers"]!.AsObject())
        {
            message = message.WithHeader(name, value!.GetValue<string>());
        }

        return message;
    }

    private static async Task<JsonNode> RunNodeAsync(string mode, JsonObject input)
    {
        var directory = Path.Combine(InteropEnvironment.RepositoryRoot, "interop", "signatures");
        var start = new ProcessStartInfo(InteropEnvironment.Get("GNAP_INTEROP_NODE", "node"))
        {
            WorkingDirectory = directory,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("crosscheck.mjs");
        start.ArgumentList.Add(mode);

        using var process = Process.Start(start)!;
        await process.StandardInput.WriteAsync(input.ToJsonString());
        process.StandardInput.Close();
        var stdout = await process.StandardOutput.ReadToEndAsync();
        var stderr = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, $"crosscheck.mjs {mode} failed: {stderr}");
        return JsonNode.Parse(stdout) ?? throw new InvalidOperationException("No output from crosscheck.mjs: " + stderr);
    }
}
