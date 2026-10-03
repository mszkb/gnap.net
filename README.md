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

## Status

**Phase 0 — HTTP Message Signatures (RFC 9421)**,
**Phase 1 — GNAP Core Primitives** and **Phase 2 — Client Library** are implemented:

| Project | Contents |
|---------|----------|
| `src/Gnap.HttpMessageSignatures` | RFC 9421 signature base canonicalization, signing/verification (Ed25519, ECDSA P-256/P-384, RSA-PSS, RSA v1.5, HMAC-SHA256), RFC 9530 `Content-Digest`, RFC 8941 structured fields, nonce replay protection (`INonceStore`), PEM key loading, `HttpClient` `DelegatingHandler` |
| `src/Gnap.HttpMessageSignatures.AspNetCore` | ASP.NET Core middleware verifying signatures and content digests on incoming requests, with optional nonce-based replay protection |
| `src/Gnap.Core` | RFC 9635 building blocks: `JsonWebKey` (EC/OKP/RSA, RFC 7638 thumbprints, conversion to signing keys), `httpsig` key proofing (string and object form with pinned `alg`/`content-digest-alg`) with nonce replay protection, the interaction finish hash and finish callback (redirect/push), `Authorization: GNAP` token presentation, and source-generated JSON models for grant requests/responses (Native-AOT-verified) |
| `src/Gnap.Client` | GNAP client without ASP.NET Core dependency: AS discovery (`OPTIONS` on the grant endpoint, `/.well-known/gnap-as-rs`, RS `WWW-Authenticate` challenge) with metadata caching, httpsig-signed grant requests (key by value/reference, instance id), redirect/push/user-code interaction with finish-hash verification, continuation and polling (`wait`, `too_fast` back-off, rotating continuation tokens), 5xx retries with fresh signatures, token rotation/revocation/key rotation, self-refreshing tokens and an `HttpClient` handler for RS calls, typed GNAP errors, `services.AddGnapClient(...)` |
| `tests/Gnap.HttpMessageSignatures.Tests` | 224 tests, including **all RFC 9421 Appendix B test vectors** (B.1 keys, B.2.1–B.2.6, B.3 proxy, B.4 transformations) and FsCheck property tests (deterministic signature base, header order/casing invariance, sign→verify for all algorithms, tamper sensitivity, RFC 8941 and `@query-param` codec roundtrips) |
| `tests/Gnap.Core.Tests` | 108 tests: RFC 7638/8037 thumbprint vectors, RFC 9635 §4.2.3 finish-hash vectors, key-proof negative tests (wrong key, tampered body/method/URI/token, replay, wrong tag/alg/keyid/digest, stale), JSON round-trips with unknown-member tolerance |
| `tests/Gnap.Client.Tests` | 93 tests against an in-memory mock AS that verifies the signature of **every** client request with the Phase 0/1 verifier (nonce replay protection on): full redirect/push/user-code flows, all 13 registered error codes, `user_denied`/`too_fast`/`unknown_interaction`, 5xx retry, finish hash valid/tampered/missing/replayed, token expiry → rotation, key rotation, discovery caching, DI |
| `tests/Gnap.Core.AotSmoke` | Native AOT smoke test: publishes Gnap.Core and Gnap.Client as a native binary (trim/AOT warnings are errors) and exercises JSON, JWK, proofing and a signed client grant at runtime |
| `examples/HttpSignatures.Demo` | Self-contained test bed: vector checks plus a live signed-client-against-Kestrel demo |
| `examples/VerifyingServer` | Standalone Kestrel resource server protected by the verification middleware |
| `examples/SigningClient` | CLI that signs requests, prints the signature base/headers and calls any URL |
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

## Building & testing

```bash
dotnet test                                        # full suite incl. RFC 9421 vectors
dotnet run --project examples/HttpSignatures.Demo  # manual test: vectors + live demo
dotnet run --project examples/GnapCore.Demo        # GNAP walkthrough + live mini-AS round trip

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
demand (`.github/workflows/mutation.yml`, `--break-at 90`).

## License

[MIT](LICENSE)
