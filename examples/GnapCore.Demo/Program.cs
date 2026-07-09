// Manual test bed for Gnap.Core (GNAP core primitives, RFC 9635).
//
//   dotnet run --project examples/GnapCore.Demo              # all parts
//   dotnet run --project examples/GnapCore.Demo -- keys      # JWKs and thumbprints
//   dotnet run --project examples/GnapCore.Demo -- models    # grant request/response JSON
//   dotnet run --project examples/GnapCore.Demo -- proofing  # httpsig key proofing offline
//   dotnet run --project examples/GnapCore.Demo -- hash      # interaction finish hash
//   dotnet run --project examples/GnapCore.Demo -- live      # signed grant request against a mini AS

using GnapCore.Demo;

var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "all";
var exitCode = 0;

if (mode is "all" or "keys")
{
    exitCode |= KeysDemo.Run();
}

if (mode is "all" or "models")
{
    exitCode |= ModelsDemo.Run();
}

if (mode is "all" or "proofing")
{
    exitCode |= await ProofingDemo.RunAsync();
}

if (mode is "all" or "hash")
{
    exitCode |= FinishHashDemo.Run();
}

if (mode is "all" or "live")
{
    exitCode |= await LiveDemo.RunAsync();
}

return exitCode;

namespace GnapCore.Demo
{
    using System.Buffers.Text;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using Gnap.Core;
    using Gnap.Core.Json;
    using Gnap.Core.Keys;
    using Gnap.Core.Models;
    using Gnap.Core.Proofing;
    using Gnap.HttpMessageSignatures;

    internal static class Output
    {
        public static void Heading(string title)
        {
            Console.WriteLine();
            Console.WriteLine($"== {title} ==");
        }

        public static void Check(bool ok, string message)
        {
            Console.WriteLine($"  {(ok ? "✓" : "✗")} {message}");
        }

        public static void PrintJson(string json, string indent = "  ")
        {
            var pretty = JsonNode.Parse(json)!.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
            foreach (var line in pretty.Split('\n'))
            {
                Console.WriteLine($"{indent}{line}");
            }
        }

        public static string NewNonce() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
    }

    internal static class DemoKeys
    {
        /// <summary>A fresh Ed25519 key pair as a JWK with private material.</summary>
        public static JsonWebKey NewEd25519(string keyId)
        {
            var privateKey = RandomNumberGenerator.GetBytes(32);
            var publicKey = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(privateKey)
                .GeneratePublicKey().GetEncoded();
            return JsonWebKey.FromEd25519(publicKey, privateKey, keyId);
        }
    }

    /// <summary>JSON Web Keys: creation, serialization and RFC 7638 thumbprints.</summary>
    internal static class KeysDemo
    {
        public static int Run()
        {
            Output.Heading("JSON Web Keys and thumbprints");

            var edKey = DemoKeys.NewEd25519("demo-ed25519");
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var ecKey = JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: "demo-p256");

            Console.WriteLine("  Public Ed25519 JWK (what a client sends to an AS):");
            Output.PrintJson(JsonSerializer.Serialize(edKey.ToPublicKey(), GnapJsonContext.Default.JsonWebKey), "    ");

            Console.WriteLine($"  Ed25519 thumbprint (RFC 7638/8037): {edKey.ComputeThumbprint()}");
            Console.WriteLine($"  P-256   thumbprint (RFC 7638):      {ecKey.ComputeThumbprint()}");

            // The thumbprint identifies the key itself: it is identical for the
            // private JWK and its public projection, and ignores kid/alg/use.
            var stable = edKey.ComputeThumbprint() == edKey.ToPublicKey().ComputeThumbprint();
            Output.Check(stable, "thumbprint is identical for private key and public projection");

            // The RFC 7638 example key must produce the RFC's thumbprint.
            var rfcKey = new JsonWebKey
            {
                Kty = "RSA",
                N = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                E = "AQAB",
            };
            var vectorOk = rfcKey.ComputeThumbprint() == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
            Output.Check(vectorOk, "RFC 7638 Section 3.1 thumbprint vector reproduced");

            // Keys convert into the RFC 9421 signature algorithms of Phase 0.
            var algorithm = ecKey.ToSignatureAlgorithm();
            Output.Check(algorithm.Name == "ecdsa-p256-sha256", $"P-256 JWK maps to '{algorithm.Name}' for HTTP signing");

            return stable && vectorOk ? 0 : 1;
        }
    }

    /// <summary>The RFC 9635 JSON models: building, serializing and parsing messages.</summary>
    internal static class ModelsDemo
    {
        public static int Run()
        {
            Output.Heading("Grant request and response models");

            var jwk = DemoKeys.NewEd25519("demo-ed25519");
            var request = new GrantRequest
            {
                AccessToken =
                [
                    new AccessTokenRequest
                    {
                        Access =
                        [
                            new AccessRight
                            {
                                Type = "photo-api",
                                Actions = ["read", "write"],
                                Locations = ["https://server.example.net/"],
                                Datatypes = ["metadata", "images"],
                            },
                            AccessRight.ForReference("dolphin-metadata"),
                        ],
                    },
                ],
                Client = new ClientInstance
                {
                    Key = GnapKey.ForHttpSig(jwk),
                    Display = new ClientDisplay { Name = "GnapCore.Demo", Uri = "https://example.net/demo" },
                },
                Interact = new InteractRequest
                {
                    Start = [new StartMode(StartModes.Redirect)],
                    Finish = new InteractFinish
                    {
                        Method = FinishMethods.Redirect,
                        Uri = "https://client.example.net/return/123455",
                        Nonce = Output.NewNonce(),
                    },
                },
                Subject = new SubjectRequest { SubIdFormats = [SubjectIdentifierFormats.Opaque] },
            };

            Console.WriteLine("  A grant request built from the typed models:");
            Output.PrintJson(GnapJson.Serialize(request), "    ");

            // The access array mixes a structured object and a reference string;
            // a single requested token serializes as an object, not an array.
            var parsed = GnapJson.DeserializeGrantRequest(GnapJson.Serialize(request))!;
            Output.Check(parsed.AccessToken!.Count == 1, "single access_token round-trips as an object");
            Output.Check(parsed.AccessToken[0].Access![1].IsReference, "access array carries the 'dolphin-metadata' reference string");

            // Parsing a typical AS response.
            var responseJson = /*lang=json,strict*/ """
                {
                    "interact": {
                        "redirect": "https://server.example.com/interact/4CF492MLVMSW9MKMXKHQ",
                        "finish": "MBDOFXG4Y5CVJCX821LH"
                    },
                    "continue": {
                        "access_token": { "value": "80UPRY5NM33OMUKMKSKU" },
                        "uri": "https://server.example.com/continue",
                        "wait": 30
                    }
                }
                """;
            var response = GnapJson.DeserializeGrantResponse(responseJson)!;
            Output.Check(response.Interact?.Redirect is not null, $"response offers interaction at {response.Interact!.Redirect}");
            Output.Check(response.Continue!.EffectiveWait == TimeSpan.FromSeconds(30), "continue.wait is honored (30 s)");

            // Errors arrive as a string or as an object; both parse into the same model.
            var terse = GnapJson.DeserializeGrantResponse(/*lang=json,strict*/ """{"error":"user_denied"}""")!;
            var verbose = GnapJson.DeserializeGrantResponse(
                /*lang=json,strict*/ """{"error":{"code":"user_denied","description":"The RO said no"}}""")!;
            Output.Check(
                terse.Error!.Code == GnapErrorCode.UserDenied && verbose.Error!.Code == GnapErrorCode.UserDenied,
                "error parses from both its string and object forms");

            // Unknown extension fields survive a round-trip (forward compatibility).
            var extended = GnapJson.DeserializeGrantRequest(
                /*lang=json,strict*/ """{"client":"client-1","future_field":{"nested":true}}""")!;
            Output.Check(
                extended.AdditionalFields!.ContainsKey("future_field")
                    && GnapJson.Serialize(extended).Contains("future_field", StringComparison.Ordinal),
                "unknown members are preserved, not dropped");

            return 0;
        }
    }

    /// <summary>httpsig key proofing: signing a request and validating the proof.</summary>
    internal static class ProofingDemo
    {
        public static async Task<int> RunAsync()
        {
            Output.Heading("httpsig key proofing (offline)");

            var jwk = DemoKeys.NewEd25519("demo-ed25519");
            const string body = /*lang=json,strict*/ """{"access_token":{"access":["dolphin-metadata"]}}""";

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://server.example.com/gnap")
            {
                Content = new StringContent(body, Encoding.UTF8, GnapConstants.MediaType),
            };
            await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);

            Console.WriteLine("  Headers the proofer attached:");
            Console.WriteLine($"    Content-Digest:  {request.Content!.Headers.GetValues("Content-Digest").First()}");
            Console.WriteLine($"    Signature-Input: {request.Headers.GetValues("Signature-Input").First()}");
            var signature = request.Headers.GetValues("Signature").First();
            Console.WriteLine($"    Signature:       {signature[..Math.Min(60, signature.Length)]}...");

            var validator = new HttpSigKeyProofValidator
            {
                NonceStore = new InMemoryNonceStore(),
                ExpectedKeyId = "demo-ed25519",
            };

            Task<KeyProofResult> ValidateAsync(string content) => validator.ValidateAsync(new KeyProofContext
            {
                Message = new HttpRequestMessageContext(request),
                Key = jwk.ToPublicKey().ToSignatureAlgorithm(),
                Content = Encoding.UTF8.GetBytes(content),
            });

            var genuine = await ValidateAsync(body);
            Output.Check(genuine.Succeeded, "genuine request validates against the public JWK");

            var tampered = await ValidateAsync(/*lang=json,strict*/ """{"access_token":{"access":["all-the-dolphins"]}}""");
            Output.Check(!tampered.Succeeded, $"tampered body is rejected ({tampered.FailureReason})");

            var replayed = await ValidateAsync(body);
            Output.Check(!replayed.Succeeded, $"replaying the same signature is rejected ({replayed.FailureReason})");

            return genuine.Succeeded && !tampered.Succeeded && !replayed.Succeeded ? 0 : 1;
        }
    }

    /// <summary>The interaction finish hash of RFC 9635 Section 4.2.3.</summary>
    internal static class FinishHashDemo
    {
        public static int Run()
        {
            Output.Heading("Interaction finish hash");

            // The four inputs of the RFC's worked example.
            const string clientNonce = "VJLO6A4CATR0KRO";
            const string asNonce = "MBDOFXG4Y5CVJCX821LH";
            const string interactRef = "4IFWWIKYB2PQ6U56NL1";
            const string grantEndpoint = "https://server.example.com/tx";

            var hash = InteractionFinishHash.Compute(clientNonce, asNonce, interactRef, grantEndpoint);
            Console.WriteLine($"  sha-256 hash: {hash}");

            var vectorOk = hash == "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY";
            Output.Check(vectorOk, "matches the RFC 9635 Section 4.2.3 example");

            var verified = InteractionFinishHash.Verify(hash, clientNonce, asNonce, interactRef, grantEndpoint);
            Output.Check(verified, "verification accepts the genuine callback");

            var forged = InteractionFinishHash.Verify(hash, clientNonce, asNonce, "FORGED-REF", grantEndpoint);
            Output.Check(!forged, "verification rejects a forged interact_ref");

            return vectorOk && verified && !forged ? 0 : 1;
        }
    }

    /// <summary>
    /// A complete round trip against a miniature in-process authorization server:
    /// signed grant request, proof validation on the AS, interaction finish with
    /// hash verification, and a signed continuation presenting the bound
    /// continuation access token — a small preview of Phases 2 and 3.
    /// </summary>
    internal static class LiveDemo
    {
        public static async Task<int> RunAsync()
        {
            Output.Heading("Live demo: signed grant request against a mini AS");

            var failures = 0;
            await using var server = await MiniAuthorizationServer.StartAsync();
            Console.WriteLine($"  Mini AS listening on {server.GrantEndpointUri}");

            var jwk = DemoKeys.NewEd25519("demo-ed25519");
            var clientNonce = Output.NewNonce();
            using var http = new HttpClient();

            // 1. Send the signed grant request.
            var grantRequest = new GrantRequest
            {
                AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("dolphin-metadata")] }],
                Client = new ClientInstance
                {
                    Key = GnapKey.ForHttpSig(jwk),
                    Display = new ClientDisplay { Name = "GnapCore.Demo" },
                },
                Interact = new InteractRequest
                {
                    Start = [new StartMode(StartModes.Redirect)],
                    Finish = new InteractFinish
                    {
                        Method = FinishMethods.Redirect,
                        Uri = "https://client.example.net/return/demo",
                        Nonce = clientNonce,
                    },
                },
            };

            var body = GnapJson.Serialize(grantRequest);
            using var signed = await CreateSignedRequestAsync(server.GrantEndpointUri, body, jwk);

            // Capture the signature headers before sending: HttpClient disposes the
            // content afterwards, and the replay/tamper probes below reuse them.
            var signatureHeaders = new SignatureHeaders(
                signed.Content!.Headers.GetValues("Content-Digest").First(),
                signed.Headers.GetValues("Signature-Input").First(),
                signed.Headers.GetValues("Signature").First());

            using var response = await http.SendAsync(signed);
            var grantResponse = JsonSerializer.Deserialize(
                await response.Content.ReadAsStringAsync(), GnapJsonContext.Default.GrantResponse)!;

            var accepted = response.IsSuccessStatusCode && grantResponse.Interact?.Finish is not null;
            Output.Check(accepted, $"AS accepted the signed grant request (HTTP {(int)response.StatusCode})");
            failures += accepted ? 0 : 1;
            Console.WriteLine($"    interact.redirect: {grantResponse.Interact?.Redirect}");
            Console.WriteLine($"    continue.uri:      {grantResponse.Continue?.Uri}");

            // 2. A replayed copy of the same signed message is rejected (nonce store).
            using var replay = CreateReplay(server.GrantEndpointUri, body, signatureHeaders);
            using var replayResponse = await http.SendAsync(replay);
            Output.Check(!replayResponse.IsSuccessStatusCode, $"replayed signature is rejected (HTTP {(int)replayResponse.StatusCode})");
            failures += replayResponse.IsSuccessStatusCode ? 1 : 0;

            // 3. A tampered body under the original signature is rejected.
            using var tampered = CreateReplay(
                server.GrantEndpointUri, body.Replace("dolphin-metadata", "all-the-dolphins", StringComparison.Ordinal), signatureHeaders);
            using var tamperedResponse = await http.SendAsync(tampered);
            Output.Check(!tamperedResponse.IsSuccessStatusCode, $"tampered body is rejected (HTTP {(int)tamperedResponse.StatusCode})");
            failures += tamperedResponse.IsSuccessStatusCode ? 1 : 0;

            // 4. The RO "approves" the request; the AS calls back with interact_ref
            //    and hash (here fetched instead of received on a callback URI).
            var callback = await http.GetFromJsonExtAsync(server.InteractionFinishUri);
            var hashOk = InteractionFinishHash.Verify(
                callback.Hash, clientNonce, grantResponse.Interact!.Finish!, callback.InteractRef, server.GrantEndpointUri);
            Output.Check(hashOk, "interaction finish hash verifies against client nonce, AS nonce and interact_ref");
            failures += hashOk ? 0 : 1;

            var forgedOk = InteractionFinishHash.Verify(
                callback.Hash, clientNonce, grantResponse.Interact.Finish!, "FORGED-REF", server.GrantEndpointUri);
            Output.Check(!forgedOk, "a forged interact_ref fails hash verification");
            failures += forgedOk ? 1 : 0;

            // 5. Continue the grant: present the key-bound continuation access token
            //    (Authorization is then covered by the signature) and the interact_ref.
            var continueBody = GnapJson.Serialize(new ContinueRequest { InteractRef = callback.InteractRef });
            using var continuation = await CreateSignedRequestAsync(
                grantResponse.Continue!.Uri!, continueBody, jwk, grantResponse.Continue.AccessToken!.Value);
            using var continueResponse = await http.SendAsync(continuation);
            var final = JsonSerializer.Deserialize(
                await continueResponse.Content.ReadAsStringAsync(), GnapJsonContext.Default.GrantResponse)!;

            var tokenIssued = continueResponse.IsSuccessStatusCode && final.AccessToken is [{ Value: not null }];
            Output.Check(tokenIssued, $"continuation returns the access token: {final.AccessToken?[0].Value}");
            failures += tokenIssued ? 0 : 1;

            return failures == 0 ? 0 : 1;
        }

        private static async Task<HttpRequestMessage> CreateSignedRequestAsync(
            string uri, string body, JsonWebKey jwk, string? accessToken = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(body, Encoding.UTF8, GnapConstants.MediaType),
            };
            if (accessToken is not null)
            {
                request.Headers.TryAddWithoutValidation(
                    "Authorization", $"{GnapConstants.AuthorizationScheme} {accessToken}");
            }

            await HttpSigKeyProofer.FromJwk(jwk).AddProofAsync(request);
            return request;
        }

        /// <summary>Rebuilds a request that reuses previously captured signature headers verbatim.</summary>
        private static HttpRequestMessage CreateReplay(string uri, string body, SignatureHeaders headers)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, uri)
            {
                Content = new StringContent(body, Encoding.UTF8, GnapConstants.MediaType),
            };
            request.Content.Headers.TryAddWithoutValidation("Content-Digest", headers.ContentDigest);
            request.Headers.TryAddWithoutValidation("Signature-Input", headers.SignatureInput);
            request.Headers.TryAddWithoutValidation("Signature", headers.Signature);
            return request;
        }

        private static async Task<(string InteractRef, string Hash)> GetFromJsonExtAsync(this HttpClient http, string uri)
        {
            var node = JsonNode.Parse(await http.GetStringAsync(uri))!;
            return (node["interact_ref"]!.GetValue<string>(), node["hash"]!.GetValue<string>());
        }

        private sealed record SignatureHeaders(string ContentDigest, string SignatureInput, string Signature);
    }
}
