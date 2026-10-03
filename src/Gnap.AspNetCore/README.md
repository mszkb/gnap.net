# Gnap.AspNetCore

GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) for ASP.NET Core: an embeddable
**authorization server** and **resource server** middleware.

## Authorization server

Grant endpoint with `httpsig` key-proof verification and nonce replay protection, redirect
and user-code interaction with browser session binding, continuation, key-bound and bearer
tokens (opaque or JWT), token rotation/revocation, RFC 9767 introspection and resource
registration, discovery. Deny-by-default `IGrantPolicy`; grant, token, client key and
resource server stores are replaceable via DI (in-memory defaults).

```csharp
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Policy;

builder.Services
    .AddGnapAuthorizationServer()                                // in-memory stores, opaque tokens
    .AddGrantPolicy(_ => GrantDecision.RequireInteraction());    // deny-by-default otherwise

app.MapGnapAuthorizationServer();   // POST /gnap/tx, /gnap/continue/…, /gnap/interact/…, /gnap/device, …
// plus a consent page at /consent that calls IGnapInteractionService.ApproveAsync/DenyAsync
```

## Resource server

`Authorization: GNAP` authentication that verifies the key proof of key-bound tokens,
validates tokens by cached RFC 9767 introspection, the co-hosted AS token store or local
JWT verification, and authorizes endpoints by GNAP access rights.

```csharp
using Gnap.AspNetCore.ResourceServer;

builder.Services.AddGnapResourceServer(o =>
{
    o.AuthorizationServer = new Uri("https://as.example");  // RFC 9767 discovery
    o.ResourceServerId = "photo-rs";                         // registered at the AS
    o.SigningKey = rsPrivateJwk;                             // signs introspection requests
});

app.UseGnapResourceServer();
app.MapGet("/photos", () => "…").RequireGnapAccess("photo-api", "read");  // 401/403 + WWW-Authenticate: GNAP
```

## Documentation

- [Running a GNAP authorization server](https://github.com/mszkb/gnap.net/blob/main/docs/gnap-authorization-server.md)
- [Protecting an API with GNAP](https://github.com/mszkb/gnap.net/blob/main/docs/gnap-resource-server.md)
- [Threat model and operator security notes](https://github.com/mszkb/gnap.net/blob/main/docs/threat-model.md)

License: MIT.
