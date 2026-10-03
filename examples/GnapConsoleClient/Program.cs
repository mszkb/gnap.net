using System.Net;
using System.Security.Cryptography;
using Gnap.Client;
using Gnap.Client.Discovery;
using Gnap.Client.Interaction;
using Gnap.Client.Tokens;
using Gnap.Core.Keys;
using Gnap.Core.Models;

// A console GNAP client using the user code flow (RFC 9635 §4.1.2/§4.1.3):
//   1. calls the resource server without a token and learns the AS from its challenge,
//   2. requests access with a fresh client key and prints the user code,
//   3. polls the AS until the resource owner approved in a browser,
//   4. calls the resource server with the key-bound token (Authorization: GNAP + signature).
//
// Usage: dotnet run --project examples/GnapConsoleClient [-- <resource URL>]
//   default resource: http://localhost:5200/photos (examples/GnapResourceServer)
var resource = new Uri(args.Length > 0 ? args[0] : Environment.GetEnvironmentVariable("RESOURCE_URL") ?? "http://localhost:5200/photos");

using var http = new HttpClient();

// 1. RS-first discovery: the 401 challenge names the grant endpoint and the access reference.
var challenge = await WaitForChallengeAsync(http, resource);
Console.WriteLine($"Resource server {resource} sent us to {challenge.AsUri} (access reference: {challenge.Access ?? "-"})");

// 2. A fresh P-256 client key, presented by value; the AS binds the tokens to it.
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var client = new GnapClient(http, new GnapClientOptions
{
    GrantEndpoint = challenge.AsUri,
    ClientKey = GnapClientKey.FromJwk(JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: "console-client")),
    Display = new ClientDisplay { Name = "GNAP console client (example)" },
});

AccessRight[] rights = challenge.Access is { } reference
    ? [AccessRight.ForReference(reference)]
    : [new AccessRight { Type = "photo-api", Actions = ["read"] }];

// 3. User code interaction; RequestAccessAsync polls (honouring wait) until approval.
var result = await client.RequestAccessAsync(rights, GnapInteractionHandler.UserCode((interaction, _) =>
{
    var code = interaction.UserCodeUri?.Code ?? interaction.UserCode;
    Console.WriteLine();
    Console.WriteLine("==============================================================");
    Console.WriteLine($"  Open {interaction.UserCodeUri?.Uri} in your browser");
    Console.WriteLine($"  and enter the code: {code}");
    Console.WriteLine("==============================================================");
    Console.WriteLine();
    Console.WriteLine("Waiting for approval (polling the AS) ...");
    return ValueTask.CompletedTask;
}));

Console.WriteLine($"Approved. Key-bound token, expires {result.AccessToken!.ExpiresAt?.ToString("u") ?? "-"}, instance id: {result.InstanceId ?? "-"}");

// 4. Call the RS: GNAP token + httpsig key proof on every request, rotation on expiry.
using var api = new HttpClient(new GnapAccessTokenHandler(client.CreateTokenSource(result.AccessToken!), new SocketsHttpHandler()));
using var response = await api.GetAsync(resource);
Console.WriteLine($"GET {resource} -> {(int)response.StatusCode} {response.StatusCode}");
Console.WriteLine(await response.Content.ReadAsStringAsync());
return response.IsSuccessStatusCode ? 0 : 1;

static async Task<GnapResourceChallenge> WaitForChallengeAsync(HttpClient http, Uri resource)
{
    // The stack may still be starting (docker compose): retry for a while.
    for (var attempt = 1; ; attempt++)
    {
        try
        {
            using var response = await http.GetAsync(resource);
            if (response.StatusCode == HttpStatusCode.Unauthorized && GnapResourceChallenge.TryParse(response, out var challenge))
            {
                return challenge;
            }

            throw new InvalidOperationException($"Expected a GNAP challenge from {resource}, got {(int)response.StatusCode}.");
        }
        catch (HttpRequestException) when (attempt < 30)
        {
            Console.WriteLine($"Waiting for {resource.GetLeftPart(UriPartial.Authority)} ...");
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }
}
