# gnap.net

A .NET implementation of the **Grant Negotiation and Authorization Protocol (GNAP,
[RFC 9635](https://datatracker.ietf.org/doc/rfc9635/))**, built incrementally in seven
phases — see the [phased implementation plan](output/gnap-dotnet-phases-plan.md).

New here? Two plain-language guides build the concepts up from zero:

- **[HTTP Message Signatures for Dummies](docs/how-it-works.md)** — the
  cryptographic foundation (Phase 0)
- **[GNAP for Dummies](docs/gnap-for-dummies.md)** — the protocol itself:
  roles, keys, key proofing, the interaction dance (Phase 1)
- **[Using Gnap.Client](docs/gnap-client.md)** — requesting access from a GNAP AS
  with the client library (Phase 2)
- **[Running a GNAP authorization server](docs/gnap-authorization-server.md)** —
  embedding the AS in ASP.NET Core with `Gnap.AspNetCore` (Phase 3)
- **[Protecting an API with GNAP](docs/gnap-resource-server.md)** — the resource
  server middleware of `Gnap.AspNetCore` (Phase 4)
- **[Interoperability](docs/interop.md)** — tested against Rafiki (Interledger),
  gnap-client-php and two JavaScript HTTP signature implementations; interop matrix,
  findings and the RFC 9635 conformance checklist (Phase 5)

## Status

**Phase 0 — HTTP Message Signatures (RFC 9421)**,
**Phase 1 — GNAP Core Primitives**, **Phase 2 — Client Library**,
**Phase 3 — Authorization Server** and **Phase 4 — Resource Server Middleware** are
implemented, and **Phase 5 — Interoperability** is verified against independent
implementations (see [docs/interop.md](docs/interop.md)):

| Peer | Flow | Status |
|------|------|--------|
| Rafiki auth server (TypeScript, Open Payments) | `Gnap.Client` → Rafiki: grant, redirect interaction + finish hash, continuation, introspection, token rotation/revocation | ✅ nightly |
| aaronpk/gnap-client-php | PHP client → `Gnap.AspNetCore` AS: full redirect flow (`sha-256`, `sha3-512`) | ✅ nightly (2-line RFC 9635 patch to the 2022 client) |
| http-message-signatures, @interledger/http-signature-utils (JS) | signatures both ways, Ed25519 + ECDSA P-256, `sha-256`/`sha-512` digests | ✅ nightly |


| Project | Contents |
|---------|----------|
| `src/Gnap.HttpMessageSignatures` | RFC 9421 signature base canonicalization, signing/verification (Ed25519, ECDSA P-256/P-384, RSA-PSS, RSA v1.5, HMAC-SHA256), RFC 9530 `Content-Digest`, RFC 8941 structured fields, nonce replay protection (`INonceStore`), PEM key loading, `HttpClient` `DelegatingHandler` |
| `src/Gnap.HttpMessageSignatures.AspNetCore` | ASP.NET Core middleware verifying signatures and content digests on incoming requests, with optional nonce-based replay protection |
| `src/Gnap.Core` | RFC 9635 building blocks: `JsonWebKey` (EC/OKP/RSA, RFC 7638 thumbprints, conversion to signing keys), `httpsig` key proofing (string and object form with pinned `alg`/`content-digest-alg`) with nonce replay protection, the interaction finish hash and finish callback (redirect/push), `Authorization: GNAP` token presentation, and source-generated JSON models for grant requests/responses (Native-AOT-verified) |
| `src/Gnap.Client` | GNAP client without ASP.NET Core dependency: AS discovery (`OPTIONS` on the grant endpoint, `/.well-known/gnap-as-rs`, RS `WWW-Authenticate` challenge) with metadata caching, httpsig-signed grant requests (key by value/reference, instance id), redirect/push/user-code interaction with finish-hash verification, continuation and polling (`wait`, `too_fast` back-off, rotating continuation tokens), 5xx retries with fresh signatures, token rotation/revocation/key rotation, self-refreshing tokens and an `HttpClient` handler for RS calls, typed GNAP errors, `services.AddGnapClient(...)` |
| `src/Gnap.AspNetCore` | **Resource server:** `AddGnapResourceServer()` + `UseGnapResourceServer()` — `Authorization: GNAP` authentication handler that verifies the `httpsig` key proof of key-bound tokens against the bound key (content digest, nonce replay protection; bearer opt-in), token validation by cached RFC 9767 introspection, the co-hosted AS token store or local JWT verification, `RequireGnapAccess("type", "action")` policies, `IGnapTokenFeature`, RFC-conformant 401/403 with `WWW-Authenticate: GNAP as_uri, access` challenge, RFC 9767 discovery and resource set registration. **Authorization server:** embeddable GNAP AS: grant endpoint with httpsig key proof verification and nonce replay protection, grant state machine, redirect and user-code interaction with browser session binding and redirect/push finish, continuation (rotating key-bound continuation tokens, `wait`, single-use `interact_ref`), key-bound and bearer tokens with pluggable `ITokenFormat` (opaque, JWT), multi-token responses, token rotation/key rotation/revocation, RFC 9767 introspection and resource registration with RS authentication, discovery; deny-by-default `IGrantPolicy`, `IGrantStore`/`ITokenStore`/`IClientKeyStore`/`IResourceServerStore` with in-memory defaults, all replaceable via DI |
| `tests/Gnap.HttpMessageSignatures.Tests` | 224 tests, including **all RFC 9421 Appendix B test vectors** (B.1 keys, B.2.1–B.2.6, B.3 proxy, B.4 transformations) and FsCheck property tests (deterministic signature base, header order/casing invariance, sign→verify for all algorithms, tamper sensitivity, RFC 8941 and `@query-param` codec roundtrips) |
| `tests/Gnap.Core.Tests` | 118 tests: RFC 7638/8037 thumbprint vectors, RFC 9635 §4.2.3 finish-hash vectors, key-proof negative tests (wrong key, tampered body/method/URI/token, replay, wrong tag/alg/keyid/digest, stale), JSON round-trips with unknown-member tolerance |
| `tests/Gnap.Client.Tests` | 94 tests against an in-memory mock AS that verifies the signature of **every** client request with the Phase 0/1 verifier (nonce replay protection on): full redirect/push/user-code flows, all 13 registered error codes, `user_denied`/`too_fast`/`unknown_interaction`, 5xx retry, finish hash valid/tampered/missing/replayed, token expiry → rotation, key rotation, discovery caching, DI |
| `tests/Gnap.AspNetCore.Tests` | 169 tests: **four-role end-to-end flows** (client → AS with RO consent → RS → protected resource, RS-first discovery via the challenge) for introspection, co-hosted token store and JWT validation; key-proof negative tests for every validation mode (unsigned, wrong key, stolen token, tampered body/digest, swapped token, stale, no nonce, replay), expired/revoked tokens, introspection cache hit/miss/expiry/invalidation, bearer opt-in, 401/403 challenges, resource registration, JWT forgery tests; plus the unmodified Phase 2 client against the real AS on a `TestServer` (redirect/push/user-code flows with simulated consent, polling, multi-token, bearer, rotation, key rotation, revocation, instance ids, key references, discovery, JWT tokens), security negative tests (replay, stale signatures, foreign/rotated/expired/unknown continuation with byte-identical errors, tampered and reused `interact_ref`, key mismatch, session binding, single-use user codes, concurrent continuations), policy, state machine, introspection and DI tests, plus the example AS via `WebApplicationFactory` (Razor consent form, EF Core) |
| `tests/Gnap.Interop.Tests` | 14 cross-implementation tests (skipped unless the peer is configured): `Gnap.Client` against Rafiki, gnap-client-php against `Gnap.AspNetCore`, HTTP signature cross-verification with two JavaScript libraries; driven by `interop/run-*.sh` and the nightly Interop workflow |
| `tests/Gnap.Core.AotSmoke` | Native AOT smoke test: publishes Gnap.Core and Gnap.Client as a native binary (trim/AOT warnings are errors) and exercises JSON, JWK, proofing and a signed client grant at runtime |
| `examples/HttpSignatures.Demo` | Self-contained test bed: vector checks plus a live signed-client-against-Kestrel demo |
| `examples/VerifyingServer` | Standalone Kestrel resource server protected by the verification middleware |
| `examples/SigningClient` | CLI that signs requests, prints the signature base/headers and calls any URL |
| `examples/GnapAuthorizationServer` | A runnable GNAP AS: `Gnap.AspNetCore` endpoints, Razor Pages consent UI (reference `IGnapInteractionService` client), EF Core/SQLite stores, a demo policy |
| `examples/GnapCore.Demo` | Guided GNAP walkthrough: JWKs and thumbprints, grant-request JSON, key proofing (incl. replay/tamper rejection), finish-hash vectors, and a live signed grant negotiation against an in-process mini AS |

Requires the **.NET 10 SDK**.

## Quickstart

Sign outgoing requests:

```csharp
using Gnap.HttpMessageSignatures;

var (publicKey, privateKey) = PemKeyLoader.LoadEd25519(pemText);
var signer = new HttpMessageSigner(SignatureAlgorithm.Ed25519(publicKey, privateKey))
{
    KeyId = "my-client",
    CoveredComponents =
    [
        SignatureComponent.Method,
        SignatureComponent.TargetUri,
        SignatureComponent.ContentDigest,
    ],
    Lifetime = TimeSpan.FromMinutes(5),
};

using var client = new HttpClient(new HttpSignatureDelegatingHandler(signer, new SocketsHttpHandler()));
// Every request now carries Content-Digest, Signature-Input and Signature fields.
```

Verify incoming requests in ASP.NET Core:

```csharp
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;

builder.Services.AddHttpMessageSignatureVerification(options =>
{
    options.KeyResolver = new StaticKeyResolver().Add("my-client", SignatureAlgorithm.Ed25519(publicKey));
    options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];

    // Optional replay protection (RFC 9421 §7.2.2): each nonce is accepted once per
    // keyid within the created + MaxAge + ClockSkew window. Clients sign with NonceLength set.
    options.NonceStore = new InMemoryNonceStore();
    options.RequireNonce = true;
});

app.UseHttpMessageSignatureVerification();
```

Nonces are recorded only after the signature verified, so forged requests cannot
"burn" a legitimate client's nonce. `InMemoryNonceStore` suits a single process;
implement `INonceStore` (atomically) over a shared cache for multi-instance deployments.

Request access as a GNAP client (console app, no ASP.NET Core needed):

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

// Call the RS: GNAP header + httpsig proof, automatic rotation on expiry.
var api = new HttpClient(new GnapAccessTokenHandler(
    client.CreateTokenSource(result.AccessToken!), new SocketsHttpHandler()));
```

See [docs/gnap-client.md](docs/gnap-client.md) for redirect/push flows, web apps,
token management, discovery, errors and DI.

Run a GNAP authorization server in ASP.NET Core:

```csharp
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Policy;

builder.Services
    .AddGnapAuthorizationServer()                                // in-memory stores, opaque tokens
    .AddGrantPolicy(_ => GrantDecision.RequireInteraction());    // deny-by-default otherwise

app.MapGnapAuthorizationServer();   // POST /gnap/tx, /gnap/continue/…, /gnap/interact/…, /gnap/device, …
// plus a consent page at /consent that calls IGnapInteractionService.ApproveAsync/DenyAsync
```

See [docs/gnap-authorization-server.md](docs/gnap-authorization-server.md) for the
policy, consent UI, storage, tokens, introspection and security properties.

Protect an API (resource server) with GNAP tokens:

```csharp
using Gnap.AspNetCore.ResourceServer;

builder.Services.AddGnapResourceServer(o =>
{
    o.AuthorizationServer = new Uri("https://as.example");  // RFC 9767 discovery
    o.ResourceServerId = "photo-rs";                         // registered at the AS
    o.SigningKey = rsPrivateJwk;                             // signs introspection requests
});                                                          // .UseJwtTokens(…) / .UseLocalTokenStore() for local verification

app.UseGnapResourceServer();
app.MapGet("/photos", () => "…").RequireGnapAccess("photo-api", "read");  // 401/403 + WWW-Authenticate: GNAP
```

See [docs/gnap-resource-server.md](docs/gnap-resource-server.md) for token
validation modes, introspection caching, authorization and error semantics.

## Building & testing

```bash
dotnet test                                        # full suite incl. RFC 9421 vectors
dotnet run --project examples/HttpSignatures.Demo  # manual test: vectors + live demo
dotnet run --project examples/GnapCore.Demo        # GNAP walkthrough + live mini-AS round trip
dotnet run --project examples/GnapAuthorizationServer --urls http://localhost:5100   # a GNAP AS with consent UI

# Native AOT smoke test for Gnap.Core + Gnap.Client (needs clang/zlib, as for any Native AOT publish)
dotnet publish tests/Gnap.Core.AotSmoke -c Release -r linux-x64 -o artifacts/aot-smoke
./artifacts/aot-smoke/Gnap.Core.AotSmoke
```

The demo starts a local Kestrel server with the verification middleware, sends a
correctly signed request (accepted), a tampered request and an unsigned request
(both rejected), and prints the signature headers so you can inspect them.

For interactive manual testing across two terminals:

```bash
# Terminal 1: resource server on http://localhost:5090
dotnet run --project examples/VerifyingServer

# Terminal 2: signed requests (accepted) vs. plain curl (rejected)
dotnet run --project examples/SigningClient                                       # GET  /api/hello -> 200
dotnet run --project examples/SigningClient -- POST /api/echo '{"amount": 10}'    # POST + Content-Digest -> 200
curl -i http://localhost:5090/api/hello                                           # unsigned -> 401
```

The client signs with the published RFC 9421 example key `test-key-ed25519`
(test use only) and prints the exact signature base so you can see what is
being signed.

### Mutation testing

The signature base builder, verifier, Content-Digest and algorithm code are
mutation-tested with [Stryker.NET](https://stryker-mutator.io/) (currently
100 % mutation score, gate at 90 %):

```bash
dotnet tool restore
dotnet stryker      # HTML report in StrykerOutput/<timestamp>/reports/
```

See [docs/mutation-testing.md](docs/mutation-testing.md) for scope, results and
the documented equivalent mutants.

## CI

GitHub Actions builds and tests on Linux and Windows for every push and pull
request (`.github/workflows/ci.yml`). Mutation testing runs nightly and on
demand (`.github/workflows/mutation.yml`, `--break-at 90`). Interoperability tests
against Rafiki, gnap-client-php and the JavaScript signature libraries run nightly
and on demand (`.github/workflows/interop.yml`, see [docs/interop.md](docs/interop.md)).

## License

[MIT](LICENSE)
