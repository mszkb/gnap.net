// Manual test bed for Gnap.HttpMessageSignatures (RFC 9421 / RFC 9530).
//
//   dotnet run --project examples/HttpSignatures.Demo            # vectors + live demo
//   dotnet run --project examples/HttpSignatures.Demo -- vectors # RFC 9421 Appendix B checks only
//   dotnet run --project examples/HttpSignatures.Demo -- live    # signed client -> Kestrel middleware only

using System.Security.Cryptography;
using System.Text;
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;
using Gnap.HttpMessageSignatures.Tests;
using HttpSignatures.Demo;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;

var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "all";
var exitCode = 0;

if (mode is "all" or "vectors")
{
    exitCode |= await Rfc9421Vectors.RunAsync();
}

if (mode is "all" or "live")
{
    exitCode |= await LiveDemo.RunAsync();
}

return exitCode;

namespace HttpSignatures.Demo
{
    /// <summary>Verifies the RFC 9421 Appendix B signatures and prints a result table.</summary>
    internal static class Rfc9421Vectors
    {
        public static async Task<int> RunAsync()
        {
            Console.WriteLine();
            Console.WriteLine("== RFC 9421 Appendix B test vectors ==");
            var verifier = new HttpMessageVerifier(new VerificationOptions { KeyResolver = Rfc9421TestVectors.AllKeys() });
            var failures = 0;

            (string Name, IHttpMessageContext Message)[] cases =
            [
                ("B.2.1 minimal rsa-pss-sha512 (sig-b21)", Signed(Rfc9421TestVectors.TestRequest(), Rfc9421TestVectors.B21SignatureInput, Rfc9421TestVectors.B21Signature)),
                ("B.2.2 selective rsa-pss-sha512 (sig-b22)", Signed(Rfc9421TestVectors.TestRequest(), Rfc9421TestVectors.B22SignatureInput, Rfc9421TestVectors.B22Signature)),
                ("B.2.3 full coverage rsa-pss-sha512 (sig-b23)", Signed(Rfc9421TestVectors.TestRequest(), Rfc9421TestVectors.B23SignatureInput, Rfc9421TestVectors.B23Signature)),
                ("B.2.4 response ecdsa-p256-sha256 (sig-b24)", Signed(Rfc9421TestVectors.TestResponse(), Rfc9421TestVectors.B24SignatureInput, Rfc9421TestVectors.B24Signature)),
                ("B.2.5 request hmac-sha256 (sig-b25)", Signed(Rfc9421TestVectors.TestRequest(), Rfc9421TestVectors.B25SignatureInput, Rfc9421TestVectors.B25Signature)),
                ("B.2.6 request ed25519 (sig-b26)", Signed(Rfc9421TestVectors.TestRequest(), Rfc9421TestVectors.B26SignatureInput, Rfc9421TestVectors.B26Signature)),
                ("B.3 TLS-terminating proxy (ttrp)", Signed(Rfc9421TestVectors.ProxyRequest(), Rfc9421TestVectors.TtrpSignatureInput, Rfc9421TestVectors.TtrpSignature)),
                ("B.4 message transformations (transform)", Signed(Rfc9421TestVectors.TransformRequest(), Rfc9421TestVectors.TransformSignatureInput, Rfc9421TestVectors.TransformSignature)),
            ];

            foreach (var (name, message) in cases)
            {
                var result = await verifier.VerifyAsync(message);
                Console.WriteLine($"  {(result.Succeeded ? "✓" : "✗")} {name}{(result.Succeeded ? "" : $" — {result.FailureReason}")}");
                if (!result.Succeeded)
                {
                    failures++;
                }
            }

            return failures == 0 ? 0 : 1;
        }

        private static SimpleHttpMessage Signed(SimpleHttpMessage message, string signatureInput, string signature) =>
            message.WithHeader("Signature-Input", signatureInput).WithHeader("Signature", signature);
    }

    /// <summary>
    /// Starts a local Kestrel server with the verification middleware, then sends a
    /// signed request (accepted), a tampered request and an unsigned request (both
    /// rejected), printing the signature headers along the way.
    /// </summary>
    internal static class LiveDemo
    {
        public static async Task<int> RunAsync()
        {
            Console.WriteLine();
            Console.WriteLine("== Live demo: signed HttpClient -> ASP.NET Core middleware ==");

            // Fresh demo key pair: the client signs with Ed25519, the server only
            // ever sees the public half.
            var seed = RandomNumberGenerator.GetBytes(32);
            var publicKey = new Ed25519PrivateKeyParameters(seed).GeneratePublicKey().GetEncoded();
            var clientKey = SignatureAlgorithm.Ed25519(publicKey, seed);
            var serverSideKey = SignatureAlgorithm.Ed25519(publicKey);

            var builder = WebApplication.CreateBuilder();
            builder.Logging.SetMinimumLevel(LogLevel.Warning);
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Services.AddHttpMessageSignatureVerification(options =>
            {
                options.KeyResolver = new StaticKeyResolver().Add("demo-client", serverSideKey);
                options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];
            });

            await using var app = builder.Build();
            app.UseHttpMessageSignatureVerification();
            app.MapPost("/api/echo", async (HttpContext context) =>
            {
                using var reader = new StreamReader(context.Request.Body);
                var body = await reader.ReadToEndAsync();
                var keyId = context.Features.Get<IHttpMessageSignatureFeature>()?.Result.Signatures[0].Parameters?.KeyId;
                return Results.Json(new { verifiedKeyId = keyId, echo = body });
            });

            await app.StartAsync();
            var baseAddress = new Uri(app.Urls.First());
            Console.WriteLine($"  Server listening on {baseAddress}");

            var failures = 0;
            failures += await SendSignedRequestAsync(baseAddress, clientKey) ? 0 : 1;
            failures += await SendTamperedRequestAsync(baseAddress, clientKey) ? 0 : 1;
            failures += await SendUnsignedRequestAsync(baseAddress) ? 0 : 1;

            await app.StopAsync();
            Console.WriteLine();
            Console.WriteLine(failures == 0
                ? "  All live demo checks behaved as expected."
                : $"  {failures} live demo check(s) did NOT behave as expected!");
            return failures == 0 ? 0 : 1;
        }

        private static HttpMessageSigner CreateSigner(SignatureAlgorithm clientKey) => new(clientKey)
        {
            KeyId = "demo-client",
            CoveredComponents =
            [
                SignatureComponent.Method,
                SignatureComponent.TargetUri,
                SignatureComponent.ContentDigest,
            ],
            Lifetime = TimeSpan.FromMinutes(5),
            NonceLength = 16,
        };

        private static async Task<bool> SendSignedRequestAsync(Uri baseAddress, SignatureAlgorithm clientKey)
        {
            Console.WriteLine();
            Console.WriteLine("  -- 1) Correctly signed request --");
            using var client = new HttpClient(new HttpSignatureDelegatingHandler(CreateSigner(clientKey), new SocketsHttpHandler()))
            {
                BaseAddress = baseAddress,
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, "/api/echo")
            {
                Content = new StringContent("{\"greeting\":\"hello\"}", Encoding.UTF8, "application/json"),
            };
            using var response = await client.SendAsync(request);

            PrintSignatureHeaders(request);
            Console.WriteLine($"     -> HTTP {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync()}");
            var ok = response.IsSuccessStatusCode;
            Console.WriteLine($"  {(ok ? "✓ accepted, as expected" : "✗ unexpectedly rejected")}");
            return ok;
        }

        private static async Task<bool> SendTamperedRequestAsync(Uri baseAddress, SignatureAlgorithm clientKey)
        {
            Console.WriteLine();
            Console.WriteLine("  -- 2) Body tampered after signing --");
            var original = Encoding.UTF8.GetBytes("{\"amount\":10}");
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(baseAddress, "/api/echo"))
            {
                Content = new StringContent("{\"amount\":10}", Encoding.UTF8, "application/json"),
            };
            request.Content.Headers.TryAddWithoutValidation("Content-Digest", ContentDigest.CreateHeaderValue(original));
            CreateSigner(clientKey).Sign(request);

            // Swap the body but keep the signed digest: a classic tampering attempt.
            request.Content = new StringContent("{\"amount\":9999}", Encoding.UTF8, "application/json");
            request.Content.Headers.TryAddWithoutValidation("Content-Digest", ContentDigest.CreateHeaderValue(original));

            using var client = new HttpClient { BaseAddress = baseAddress };
            using var response = await client.SendAsync(request);

            Console.WriteLine($"     -> HTTP {(int)response.StatusCode}");
            var ok = response.StatusCode == System.Net.HttpStatusCode.Unauthorized;
            Console.WriteLine($"  {(ok ? "✓ rejected, as expected" : "✗ unexpectedly accepted")}");
            return ok;
        }

        private static async Task<bool> SendUnsignedRequestAsync(Uri baseAddress)
        {
            Console.WriteLine();
            Console.WriteLine("  -- 3) Unsigned request --");
            using var client = new HttpClient { BaseAddress = baseAddress };
            using var response = await client.PostAsync("/api/echo", new StringContent("{}", Encoding.UTF8, "application/json"));

            Console.WriteLine($"     -> HTTP {(int)response.StatusCode}");
            var ok = response.StatusCode == System.Net.HttpStatusCode.Unauthorized;
            Console.WriteLine($"  {(ok ? "✓ rejected, as expected" : "✗ unexpectedly accepted")}");
            return ok;
        }

        private static void PrintSignatureHeaders(HttpRequestMessage request)
        {
            Console.WriteLine($"     Content-Digest:  {string.Join(", ", request.Content!.Headers.GetValues("Content-Digest"))}");
            Console.WriteLine($"     Signature-Input: {string.Join(", ", request.Headers.GetValues("Signature-Input"))}");
            Console.WriteLine($"     Signature:       {string.Join(", ", request.Headers.GetValues("Signature"))}");
        }
    }
}
