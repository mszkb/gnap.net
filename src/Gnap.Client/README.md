# Gnap.Client

A client for GNAP, the Grant Negotiation and Authorization Protocol
([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)). No ASP.NET Core dependency; trimming
and Native AOT compatible.

- AS discovery (grant endpoint `OPTIONS`, `/.well-known/gnap-as-rs`, RS
  `WWW-Authenticate` challenges) with metadata caching
- `httpsig`-signed grant requests (key by value or reference, instance identifiers)
- Redirect, push and user-code interaction with finish-hash verification
- Continuation and polling (`wait`, `too_fast` back-off, rotating continuation tokens)
- Token rotation, revocation and key rotation; self-refreshing tokens and an `HttpClient`
  handler for resource server calls
- Typed GNAP errors and `services.AddGnapClient(...)` for `IHttpClientFactory`/DI

## Quickstart

```csharp
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Client.Tokens;
using Gnap.Core.Models;

var client = new GnapClient(new HttpClient(), new GnapClientOptions
{
    GrantEndpoint = new Uri("https://as.example/tx"),
    ClientKey = GnapClientKey.FromJwk(privateJwk),
});

var result = await client.RequestAccessAsync(
    [AccessRight.ForReference("photo-api")],
    GnapInteractionHandler.UserCode((i, _) =>
    {
        Console.WriteLine($"Enter {i.UserCode} at the AS");
        return ValueTask.CompletedTask;
    }));

// Call the RS: Authorization: GNAP + httpsig proof, automatic rotation on expiry.
var api = new HttpClient(new GnapAccessTokenHandler(
    client.CreateTokenSource(result.AccessToken!), new SocketsHttpHandler()));
```

Documentation: [Using Gnap.Client](https://github.com/mszkb/gnap.net/blob/main/docs/gnap-client.md)
(redirect/push flows, web apps, token management, discovery, errors, DI). Tested against
the [Rafiki](https://github.com/interledger/rafiki) authorization server. License: MIT.
