# Gnap.Core

Protocol-neutral building blocks of GNAP, the Grant Negotiation and Authorization Protocol
([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)), shared by
[`Gnap.Client`](https://www.nuget.org/packages/Gnap.Client) and
[`Gnap.AspNetCore`](https://www.nuget.org/packages/Gnap.AspNetCore):

- `JsonWebKey` for EC, OKP (Ed25519) and RSA keys with RFC 7638 thumbprints and conversion
  to signing/verification keys
- `httpsig` key proofing (RFC 9635 §7.3.1) on top of RFC 9421, with pinned `alg` /
  `content-digest-alg` and nonce replay protection
- The interaction finish hash (RFC 9635 §4.2.3) and finish callback handling
- `Authorization: GNAP` token presentation
- Source-generated `System.Text.Json` models for grant requests and responses, tolerant of
  unknown members; trimming and Native AOT compatible

Most applications use this package indirectly through the client or ASP.NET Core packages.

```csharp
using Gnap.Core;

// RFC 9635 §4.2.3 interaction finish hash (sha-256 by default), verified in constant time
string hash = InteractionFinishHash.Compute(clientNonce, asNonce, interactRef, "https://as.example/tx");
bool ok = InteractionFinishHash.Verify(receivedHash, clientNonce, asNonce, interactRef, "https://as.example/tx");
```

Documentation: [GNAP for Dummies](https://github.com/mszkb/gnap.net/blob/main/docs/gnap-for-dummies.md),
[repository](https://github.com/mszkb/gnap.net). License: MIT.
