// A standalone resource server protected by HTTP Message Signatures (RFC 9421).
//
//   dotnet run --project examples/VerifyingServer          # listens on http://localhost:5090
//
// Manual testing:
//   dotnet run --project examples/SigningClient                                        # signed GET  -> 200
//   dotnet run --project examples/SigningClient -- POST /api/echo '{"amount": 10}'     # signed POST -> 200
//   curl -i http://localhost:5090/api/hello                                            # unsigned    -> 401
//
// The server accepts the well-known RFC 9421 example keys `test-key-ed25519` and
// `test-key-ecc-p256`. These are published test keys — never use them in production.

using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;
using VerifyingServer;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls("http://localhost:5090");

var (edPublicKey, _) = PemKeyLoader.LoadEd25519(DemoKeys.Ed25519TestKeyPem);
builder.Services.AddHttpMessageSignatureVerification(options =>
{
    options.KeyResolver = new StaticKeyResolver()
        .Add("test-key-ed25519", SignatureAlgorithm.Ed25519(edPublicKey))
        .Add("test-key-ecc-p256", SignatureAlgorithm.EcdsaP256Sha256(PemKeyLoader.LoadEcdsa(DemoKeys.EccP256TestKeyPem)));
    options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];
    options.MaxAge = TimeSpan.FromMinutes(10);
    options.NonceStore = new InMemoryNonceStore();
});

var app = builder.Build();
app.UseHttpMessageSignatureVerification();

app.MapGet("/api/hello", (HttpContext context) => Results.Json(new
{
    message = "hello, signed world",
    verifiedKeyId = context.SignatureKeyId(),
}));

app.MapPost("/api/echo", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();
    return Results.Json(new
    {
        verifiedKeyId = context.SignatureKeyId(),
        coveredComponents = context.Features.Get<IHttpMessageSignatureFeature>()?
            .Result.Signatures[0].Parameters?.Components.Select(c => c.ToString()),
        echo = body,
    });
});

Console.WriteLine("Verifying server ready on http://localhost:5090");
Console.WriteLine("  GET  /api/hello   POST /api/echo   (both require a valid signature)");
app.Run();

namespace VerifyingServer
{
    internal static class HttpContextExtensions
    {
        public static string? SignatureKeyId(this HttpContext context) =>
            context.Features.Get<IHttpMessageSignatureFeature>()?.Result.Signatures[0].Parameters?.KeyId;
    }

    /// <summary>The published RFC 9421 example keys (Appendix B.1) — for testing only.</summary>
    internal static class DemoKeys
    {
        public const string Ed25519TestKeyPem = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
            -----END PUBLIC KEY-----
            """;

        public const string EccP256TestKeyPem = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
            w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
            -----END PUBLIC KEY-----
            """;
    }
}
