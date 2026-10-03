using System.Security.Cryptography;
using System.Text;
using Gnap.Client;
using Gnap.Client.Discovery;
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;
using Gnap.HttpMessageSignatures;

// Exercises the reflection-sensitive code paths of Gnap.Core (source-generated
// JSON including the hand-written union converters, JWK conversion and httpsig
// proofing) so a native AOT build proves them trimming- and AOT-safe at runtime.
const string GrantRequestJson = /*lang=json,strict*/ """
    {
        "access_token": [
            { "label": "a", "access": [ { "type": "photo-api", "actions": ["read"], "x-ext": 1 }, "dolphin-metadata" ] },
            { "label": "b", "access": [ "ref" ], "flags": ["bearer"] }
        ],
        "client": { "key": { "proof": { "method": "httpsig", "alg": "ecdsa-p256-sha256" }, "jwk": { "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "kid": "k" } } },
        "user": "user-ref",
        "interact": { "start": ["redirect", { "mode": "ext", "p": true }], "finish": { "method": "push", "uri": "https://c.example/p", "nonce": "n" } },
        "subject": { "sub_id_formats": ["opaque"] },
        "unknown": { "kept": true }
    }
    """;

const string GrantResponseJson = /*lang=json,strict*/ """
    {
        "continue": { "uri": "https://as.example/continue", "wait": 30, "access_token": { "value": "c" } },
        "access_token": { "value": "t", "access": ["r"], "key": "key-ref", "flags": ["durable"] },
        "interact": { "redirect": "https://as.example/i", "finish": "as-nonce", "user_code_uri": { "code": "A1", "uri": "https://as.example/u" } },
        "subject": { "sub_ids": [ { "format": "opaque", "id": "J2G8G8O4AZ" } ], "updated_at": "2026-01-01T00:00:00Z" },
        "error": { "code": "user_denied", "description": "no" }
    }
    """;

var failures = 0;

var request = GnapJson.DeserializeGrantRequest(GrantRequestJson)!;
Check(request.AccessToken!.Count == 2, "multiple access token requests");
Check(request.AccessToken[0].Access![0].AdditionalFields!.ContainsKey("x-ext"), "access right extension field");
Check(request.Client!.Key!.Proof!.HttpSigAlgorithm == "ecdsa-p256-sha256", "proof method object form");
Check(request.User!.IsReference, "user reference");
Check(request.AdditionalFields!.ContainsKey("unknown"), "unknown member preserved");
Check(GnapJson.DeserializeGrantRequest(GnapJson.Serialize(request)) is not null, "grant request round trip");

var response = GnapJson.DeserializeGrantResponse(GrantResponseJson)!;
Check(response.Error!.Code == GnapErrorCode.UserDenied, "error object form");
Check(response.AccessToken![0].Key!.IsReference, "key reference");
Check(response.Interact!.UserCodeUri!.Code == "A1", "user_code_uri");
Check(GnapJson.DeserializeGrantResponse(GnapJson.Serialize(response)) is not null, "grant response round trip");

var callback = new InteractionFinishCallback { Hash = "h", InteractRef = "r" };
Check(GnapJson.DeserializeFinishCallback(GnapJson.Serialize(callback))!.InteractRef == "r", "finish callback round trip");

using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var jwk = JsonWebKey.FromECDsa(ec, includePrivateKey: true, keyId: "aot-key");
Check(jwk.ComputeThumbprint().Length == 43, "thumbprint");

var presentedKey = GnapKey.ForHttpSig(jwk, ContentDigestAlgorithm.Sha512);
using var message = new HttpRequestMessage(HttpMethod.Post, "https://as.example/gnap")
{
    Content = new StringContent(GrantRequestJson, Encoding.UTF8, "application/json"),
};
await new HttpSigKeyProofer(jwk.ToSignatureAlgorithm(), jwk.Kid) { ContentDigestAlgorithm = ContentDigestAlgorithm.Sha512 }
    .AddProofAsync(message);
var proof = await HttpSigKeyProofValidator.ForKey(presentedKey).ValidateAsync(new KeyProofContext
{
    Message = new HttpRequestMessageContext(message),
    Key = presentedKey.ToSignatureAlgorithm(),
    Content = Encoding.UTF8.GetBytes(GrantRequestJson),
});
Check(proof.Succeeded, $"httpsig proof ({proof.FailureReason})");

Check(InteractionFinishHash.Compute("c", "a", "r", "https://as.example/gnap").Length == 43, "finish hash");
Check(GnapAuthorization.TryParse(GnapAuthorization.CreateHeaderValue("t0k3n"), out var token) && token == "t0k3n", "authorization header");

// Gnap.Client: discovery (its own source-generated context) and a signed grant round trip.
using var staticAs = new StaticAuthorizationServer();
using var asHttp = new HttpClient(staticAs);
var gnapClient = new GnapClient(asHttp, new GnapClientOptions
{
    GrantEndpoint = new Uri("https://as.example/tx"),
    ClientKey = GnapClientKey.FromJwk(jwk),
});
var metadata = await gnapClient.DiscoverAsync();
Check(metadata.SupportsStartMode(StartModes.Redirect) && metadata.KeyRotationSupported == true, "client discovery");
var grant = await gnapClient.RequestAccessAsync([AccessRight.ForReference("r")]);
Check(grant.AccessToken?.Value == "t" && grant.AccessToken.BoundKey is not null, "client grant");
Check(staticAs.SawSignedGrantRequest, "client grant request signed");
Check(GnapResourceChallenge.TryParse("GNAP as_uri=\"https://as.example/tx\", access=\"a\"", out var challenge) && challenge.Access == "a", "RS challenge");

Console.WriteLine(failures == 0 ? "Gnap.Core/Gnap.Client AOT smoke test passed." : $"{failures} check(s) failed.");
return failures == 0 ? 0 : 1;

void Check(bool condition, string what)
{
    if (!condition)
    {
        Console.Error.WriteLine($"FAIL: {what}");
        failures++;
    }
}

/// <summary>A canned AS: answers discovery and issues a token for any signed grant request.</summary>
internal sealed class StaticAuthorizationServer : HttpMessageHandler
{
    public bool SawSignedGrantRequest { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string json;
        if (request.Method == HttpMethod.Options)
        {
            json = /*lang=json,strict*/ """
                { "grant_request_endpoint": "https://as.example/tx", "interaction_start_modes_supported": ["redirect"], "key_rotation_supported": true }
                """;
        }
        else
        {
            SawSignedGrantRequest = request.Headers.Contains("Signature") && request.Headers.Contains("Signature-Input");
            json = /*lang=json,strict*/ """{ "access_token": { "value": "t", "access": ["r"] } }""";
        }

        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json"),
        });
    }
}
