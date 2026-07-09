# gnap.net

A .NET implementation of the **Grant Negotiation and Authorization Protocol (GNAP,
[RFC 9635](https://datatracker.ietf.org/doc/rfc9635/))**, built incrementally in seven
phases — see the [phased implementation plan](output/gnap-dotnet-phases-plan.md).

New here? Two plain-language guides build the concepts up from zero:

- **[HTTP Message Signatures for Dummies](docs/how-it-works.md)** — the
  cryptographic foundation (Phase 0)
- **[GNAP for Dummies](docs/gnap-for-dummies.md)** — the protocol itself:
  roles, keys, key proofing, the interaction dance (Phase 1)

## Status

**Phase 0 — HTTP Message Signatures (RFC 9421)** and
**Phase 1 — GNAP Core Primitives** are implemented:

| Project | Contents |
|---------|----------|
| `src/Gnap.HttpMessageSignatures` | RFC 9421 signature base canonicalization, signing/verification (Ed25519, ECDSA P-256/P-384, RSA-PSS, RSA v1.5, HMAC-SHA256), RFC 9530 `Content-Digest`, RFC 8941 structured fields, PEM key loading, `HttpClient` `DelegatingHandler` |
| `src/Gnap.HttpMessageSignatures.AspNetCore` | ASP.NET Core middleware verifying signatures and content digests on incoming requests |
| `src/Gnap.Core` | RFC 9635 building blocks: `JsonWebKey` (EC/OKP/RSA, RFC 7638 thumbprints, conversion to signing keys), `httpsig` key proofing with nonce replay protection, the interaction finish hash, and source-generated JSON models for grant requests/responses |
| `tests/Gnap.HttpMessageSignatures.Tests` | 116 tests, including **all RFC 9421 Appendix B test vectors** (B.1 keys, B.2.1–B.2.6, B.3 proxy, B.4 transformations) |
| `tests/Gnap.Core.Tests` | 67 tests: RFC 7638/8037 thumbprint vectors, RFC 9635 §4.2.3 finish-hash vectors, key-proof negative tests (wrong key, tampered body, replay, …), JSON round-trips with unknown-member tolerance |
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
});

app.UseHttpMessageSignatureVerification();
```

## Building & testing

```bash
dotnet test                                        # full suite incl. RFC 9421 vectors
dotnet run --project examples/HttpSignatures.Demo  # manual test: vectors + live demo
dotnet run --project examples/GnapCore.Demo        # GNAP walkthrough + live mini-AS round trip
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

## CI

GitHub Actions builds and tests on Linux and Windows for every push and pull
request (`.github/workflows/ci.yml`).

## License

[MIT](LICENSE)
