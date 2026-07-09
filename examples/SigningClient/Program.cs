// A command-line client that signs HTTP requests per RFC 9421 and prints the
// signature base, the signature headers and the response.
//
//   dotnet run --project examples/SigningClient                                     # GET  http://localhost:5090/api/hello
//   dotnet run --project examples/SigningClient -- POST /api/echo '{"amount": 10}'  # POST with signed Content-Digest
//   dotnet run --project examples/SigningClient -- GET https://example.com/api      # any absolute URL works
//
// Signs with the published RFC 9421 example key `test-key-ed25519`, which the
// VerifyingServer example accepts. Test key only — never use it in production.

using System.Text;
using Gnap.HttpMessageSignatures;

const string Ed25519TestKeyPem = """
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
    -----END PUBLIC KEY-----

    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
    -----END PRIVATE KEY-----
    """;

var method = new HttpMethod(args.Length > 0 ? args[0].ToUpperInvariant() : "GET");
var target = args.Length > 1 ? args[1] : "/api/hello";
var body = args.Length > 2 ? args[2] : null;
var url = target.StartsWith("http", StringComparison.OrdinalIgnoreCase)
    ? new Uri(target)
    : new Uri(new Uri("http://localhost:5090"), target);

var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(Ed25519TestKeyPem);
var components = new List<SignatureComponent>
{
    SignatureComponent.Method,
    SignatureComponent.TargetUri,
};
if (body is not null)
{
    components.Add(SignatureComponent.ContentDigest);
}

var signer = new HttpMessageSigner(SignatureAlgorithm.Ed25519(publicKey, privateKey))
{
    KeyId = "test-key-ed25519",
    CoveredComponents = components,
    Lifetime = TimeSpan.FromMinutes(5),
    NonceLength = 16,
};

using var request = new HttpRequestMessage(method, url);
if (body is not null)
{
    request.Content = new StringContent(body, Encoding.UTF8, "application/json");
    request.Content.Headers.TryAddWithoutValidation(
        "Content-Digest",
        ContentDigest.CreateHeaderValue(Encoding.UTF8.GetBytes(body)));
}

var result = signer.Sign(request);

Console.WriteLine($"{method} {url}");
Console.WriteLine();
Console.WriteLine("Signature base:");
foreach (var line in result.SignatureBase.Split('\n'))
{
    Console.WriteLine($"  {line}");
}

Console.WriteLine();
Console.WriteLine("Request headers:");
if (body is not null)
{
    Console.WriteLine($"  Content-Digest:  {string.Join(", ", request.Content!.Headers.GetValues("Content-Digest"))}");
}

Console.WriteLine($"  Signature-Input: {result.SignatureInput}");
Console.WriteLine($"  Signature:       {result.Signature}");
Console.WriteLine();

try
{
    using var client = new HttpClient();
    using var response = await client.SendAsync(request);
    Console.WriteLine($"-> HTTP {(int)response.StatusCode} {response.StatusCode}");
    var responseBody = await response.Content.ReadAsStringAsync();
    if (responseBody.Length > 0)
    {
        Console.WriteLine(responseBody);
    }

    return response.IsSuccessStatusCode ? 0 : 1;
}
catch (HttpRequestException e)
{
    Console.WriteLine($"-> request failed: {e.Message}");
    Console.WriteLine("   (is the VerifyingServer example running? dotnet run --project examples/VerifyingServer)");
    return 2;
}
