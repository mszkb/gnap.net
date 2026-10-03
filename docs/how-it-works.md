# HTTP Message Signatures for Dummies

*A plain-language guide to what this library does and how it works.*

This document explains **Phase 0** of gnap.net: the `Gnap.HttpMessageSignatures`
library, which implements **HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421))**
and **Content-Digest ([RFC 9530](https://www.rfc-editor.org/rfc/rfc9530))**.
No prior crypto knowledge required — we build everything up from "why would I
even want this?".

---

## Table of contents

1. [The problem: HTTP messages can be forged](#1-the-problem-http-messages-can-be-forged)
2. [The idea: sign the parts that matter](#2-the-idea-sign-the-parts-that-matter)
3. [The big picture](#3-the-big-picture)
4. [Key concept #1: the signature base](#4-key-concept-1-the-signature-base)
5. [Key concept #2: the two signature headers](#5-key-concept-2-the-two-signature-headers)
6. [Key concept #3: protecting the body with Content-Digest](#6-key-concept-3-protecting-the-body-with-content-digest)
7. [What happens when you sign (step by step)](#7-what-happens-when-you-sign-step-by-step)
8. [What happens when the server verifies (step by step)](#8-what-happens-when-the-server-verifies-step-by-step)
9. [Map of the library: which class does what](#9-map-of-the-library-which-class-does-what)
10. [Using it: the client side](#10-using-it-the-client-side)
11. [Using it: the server side](#11-using-it-the-server-side)
12. [Keys and algorithms: which one do I pick?](#12-keys-and-algorithms-which-one-do-i-pick)
13. [Try it yourself: the example apps](#13-try-it-yourself-the-example-apps)
14. [Why signatures survive proxies (and when they don't)](#14-why-signatures-survive-proxies-and-when-they-dont)
15. [Security features you get for free](#15-security-features-you-get-for-free)
16. [FAQ and common pitfalls](#16-faq-and-common-pitfalls)
17. [Glossary](#17-glossary)

---

## 1. The problem: HTTP messages can be forged

TLS (the "s" in https) encrypts the *connection* between two machines. That is
great, but it has two blind spots:

1. **TLS proves nothing about *who sent* the message.** Anyone can open a TLS
   connection to your API. A bearer token in a header helps, but if that token
   leaks (a log file, a proxy, a browser extension), whoever holds it can send
   *any* request they like.
2. **TLS ends at the edge.** Load balancers and reverse proxies terminate TLS
   and forward plain HTTP internally. Everything behind the edge just *trusts*
   what it receives.

What we actually want is a way for the receiver to check, per message:

> "Was this exact request — this method, this URL, this body — created by
> someone holding a specific private key, recently, and not altered on the way?"

That is exactly what HTTP Message Signatures provide.

## 2. The idea: sign the parts that matter

A digital signature is a small piece of data computed from (a) a message and
(b) a **private key**. Anyone with the matching **public key** can check that
the signature fits the message. Change even one character of the message and
the check fails. Without the private key, nobody can produce a valid signature.

You *could* try to sign the whole raw HTTP message, byte for byte. That fails
in practice, because HTTP messages legitimately change in transit: proxies
reorder headers, merge duplicate headers, add `Via` or `X-Forwarded-For`, and
so on. A byte-exact signature would break constantly.

RFC 9421's solution: **don't sign the raw message — sign a carefully rebuilt
summary of it**, called the **signature base**. The sender picks which parts
of the message are covered ("the method, the URL, the content digest"), both
sides rebuild the same summary using strict rules, and the signature is made
over that summary. Anything *not* covered may change freely in transit without
breaking the signature.

## 3. The big picture

```
  CLIENT                                            SERVER
  ------                                            ------
  1. Build request                                  5. Receive request
  2. Pick covered components                        6. Read Signature-Input:
     (@method, @target-uri,                            which components were covered,
      content-digest, ...)                             which key was used
  3. Build the SIGNATURE BASE          ─────►       7. Rebuild the SIGNATURE BASE
     and sign it with the                              from the received message
     PRIVATE key                                       (same strict rules!)
  4. Attach two headers:                            8. Verify the signature with
     Signature-Input: what was signed                  the PUBLIC key
     Signature:       the signature                 9. Check timestamps & policy
                                                   10. Accept (200) or reject (401)
```

The magic is in steps 3 and 7: **both sides independently build the exact same
text** from the message. If the message was tampered with in any covered part,
the server builds a *different* text, and the signature no longer matches.

## 4. Key concept #1: the signature base

The signature base is just a multi-line string. One line per covered
component, plus a final line describing the signature itself. For this request:

```
POST /foo?param=Value&Pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/...:
Content-Length: 18

{"hello": "world"}
```

...covering the date header, method, path, and more, the signature base looks
like this (taken verbatim from RFC 9421, test case B.2.3 — our test suite
reproduces it byte for byte):

```
"date": Tue, 20 Apr 2021 02:07:55 GMT
"@method": POST
"@path": /foo
"@query": ?param=Value&Pet=dog
"@authority": example.com
"content-type": application/json
"content-digest": sha-512=:WZDPaVn/...:
"content-length": 18
"@signature-params": ("date" "@method" "@path" "@query" \
  "@authority" "content-type" "content-digest" "content-length")\
  ;created=1618884473;keyid="test-key-rsa-pss"
```

Things to notice:

- **Ordinary header lines** like `"date": ...` are simply the header name
  (lowercased, in quotes) and its cleaned-up value.
- **Lines starting with `@`** are *derived components*: values that don't live
  in a single header but are derived from the request itself — the method
  (`@method`), the path (`@path`), the query string (`@query`), the host
  (`@authority`), the full URL (`@target-uri`), or the response status code
  (`@status`). There is even `@query-param` to pin one specific query
  parameter.
- **The last line `"@signature-params"`** is the signature's own metadata: the
  list of covered components (so the order can be reproduced!), when it was
  created, and which key was used. Because this line is *part of the signed
  text*, an attacker cannot quietly remove components from coverage or swap
  the key id — that would change the base and break the signature.

The cleanup rules ("canonicalization") are what make this robust: header names
are lowercased, whitespace is trimmed, and duplicate headers are joined with
`", "`. So it doesn't matter whether a proxy writes `DATE` or `date`, or
splits `Accept` over two lines — both sides still produce identical text.

In this library, the class that builds this string is
[`SignatureBaseBuilder`](../src/Gnap.HttpMessageSignatures/SignatureBaseBuilder.cs).

## 5. Key concept #2: the two signature headers

The result of signing travels in two headers, both formatted as
"structured fields" (RFC 8941 — a strict, machine-friendly header syntax):

```
Signature-Input: sig1=("@method" "@target-uri" "content-digest")
                 ;created=1783617077;expires=1783617377
                 ;nonce="buosYu9E...";keyid="test-key-ed25519"
Signature:       sig1=:R8KKBUAq3YcItgNmKogXM3Lv+...:
```

- **`Signature-Input`** says *what* was signed and *with which parameters*.
  It repeats exactly the content of the `"@signature-params"` base line.
- **`Signature`** carries the actual signature bytes, base64-encoded between
  colons.
- **`sig1`** is a *label*. It links the two headers together and allows
  **multiple signatures on one message** (e.g. the client signs, then an
  API gateway adds its own signature under a different label).

The parameters you will meet:

| Parameter | Meaning |
|-----------|---------|
| `created` | Unix timestamp when the signature was made |
| `expires` | Unix timestamp after which it is invalid |
| `keyid`   | Name of the key, so the verifier knows which public key to use |
| `nonce`   | Random one-time value (helps against replaying old requests) |
| `alg`     | Optional: announces the algorithm (the verifier must double-check it!) |
| `tag`     | Optional: application-specific marker |

## 6. Key concept #3: protecting the body with Content-Digest

Careful readers noticed: the covered components are headers and URL parts —
**the body is never signed directly**. Bodies can be huge or streamed, so
RFC 9421 does not cover them.

The trick (from RFC 9530): put a **hash of the body** into a header, and sign
*that header*.

```
Content-Digest: sha-256=:qsg/SBB198qg4FxUCDpFdhp3uwhQ7oiYIIrftNgHR+g=:
```

Now the chain is: *body → digest header → signature*.

- If someone alters the body, the digest no longer matches the body
  → server rejects.
- If someone alters the digest header to match the new body, the signature
  no longer matches → server rejects.

In this library: [`ContentDigest`](../src/Gnap.HttpMessageSignatures/ContentDigest.cs)
computes/validates the header, the client handler adds it automatically, and
the server middleware checks it against the actual received bytes.

## 7. What happens when you sign (step by step)

Say you run this code:

```csharp
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
    NonceLength = 16,
};
signer.Sign(request);   // request is an HttpRequestMessage
```

Internally, `HttpMessageSigner.Sign` does:

1. **Collect the signature parameters.** Current time → `created`; plus five
   minutes → `expires`; 16 random bytes → `nonce`; your `KeyId` → `keyid`.
2. **Build the signature base** via `SignatureBaseBuilder`: one line per
   covered component, resolved from the actual request, plus the
   `"@signature-params"` line.
3. **Sign the base.** The UTF-8 bytes of that string go into the algorithm
   (here Ed25519) together with the private key. Out comes a small byte array.
4. **Attach the headers.** `Signature-Input: sig1=(...)...` and
   `Signature: sig1=:base64:` are added to the request.

If you use `HttpSignatureDelegatingHandler`, there is a step 0: for requests
with a body it first buffers the content, computes `Content-Digest`, and only
then signs — so the digest is covered.

## 8. What happens when the server verifies (step by step)

On the server, `HttpMessageVerifier.VerifyAsync` (or the ASP.NET Core
middleware wrapping it) does the reverse:

1. **Parse** the `Signature-Input` and `Signature` headers (strict RFC 8941
   parsing — malformed headers are rejected, not guessed at).
2. For each signature label:
3. **Rebuild the signature base** from the *received* message, using the
   component list from `Signature-Input`. If a covered header is missing from
   the message → reject.
4. **Check timestamps**: `created` must not be in the future, `expires` must
   not have passed, and (if configured) the signature must not be older than
   `MaxAge`. A configurable clock skew (default 5 minutes) absorbs clock
   differences between machines.
5. **Check policy**: does the signature cover everything the server insists on
   (`RequiredComponents`, e.g. method + target URI)? A signature that covers
   nothing is trivially replayable, so servers should demand coverage.
6. **Resolve the key**: the `keyid` is looked up via your
   `IVerificationKeyResolver`. Unknown key → reject. If the signature
   announces an `alg`, it must match the resolved key's algorithm — this
   prevents "algorithm confusion" attacks where an attacker re-labels an RSA
   signature as HMAC.
7. **Verify the crypto**: public key + rebuilt base + received signature
   bytes → valid or not.

The middleware additionally validates `Content-Digest` against the actual
body bytes *after* the signature has been verified (the signature covers the
`Content-Digest` header, not the body, so it can be checked first). Requests
that are not authenticated are therefore rejected without reading a single
body byte. The body is hashed incrementally while it is read and buffered
(and rewound, so your endpoint can still read it normally) only up to
`MaxBufferedContentLength` (default 1 MiB). The limit is enforced while
reading, so it also holds for bodies without a `Content-Length`
(`Transfer-Encoding: chunked`, HTTP/2): anything larger is rejected with 401.

One deliberate design decision: on failure the client gets a **generic 401**.
The precise reason ("expired", "unknown key", ...) goes to the server log
only. Detailed error answers would hand attackers an oracle for probing.

## 9. Map of the library: which class does what

```
Gnap.HttpMessageSignatures                       (no ASP.NET dependency)
│
├── StructuredFields/            RFC 8941 parser + canonical serializer.
│   ├── SfParser                 Parses "sig1=(...);created=..." style headers.
│   └── SfValue / SfItem / ...   The value model (strings, integers, byte
│                                sequences, inner lists, dictionaries).
│
├── SignatureComponent           One coverable thing: a header name or a
│                                derived component (@method, @query-param...).
│                                Factories: .Method, .TargetUri, .Field("date"),
│                                .QueryParam("Pet"), .WithRequest(), ...
│
├── SignatureParameters          The covered-components list + created/expires/
│                                keyid/nonce/alg/tag. Serializes to the exact
│                                Signature-Input member text.
│
├── SignatureBaseBuilder         THE core: message + parameters → canonical
│                                signature base string (Section 4 above).
│
├── SignatureAlgorithm           Crypto behind one name: Ed25519 (BouncyCastle),
│                                EcdsaP256Sha256, EcdsaP384Sha384, RsaPssSha512,
│                                RsaV15Sha256, HmacSha256. Sign() + Verify().
│
├── PemKeyLoader                 Reads keys from PEM text, including the odd
│                                RSASSA-PSS PKCS#8 format .NET rejects natively.
│
├── HttpMessageSigner            Signing workflow (Section 7).
├── HttpMessageVerifier          Verification workflow (Section 8).
├── IVerificationKeyResolver     Your hook: keyid → key. StaticKeyResolver is
│                                a ready-made in-memory implementation.
├── INonceStore                  Replay memory (nonce per keyid until the
│                                acceptance window ends). InMemoryNonceStore
│                                included; implement over Redis/DB for clusters.
│
├── ContentDigest                RFC 9530 Content-Digest create + validate.
├── HttpSignatureDelegatingHandler   Plug into HttpClient: auto digest + sign.
├── IHttpMessageContext          Abstraction over "a message": adapters exist
│   ├── HttpRequestMessageContext / HttpResponseMessageContext  (HttpClient)
│   └── SimpleHttpMessage        In-memory builder for tests and tools.
│
Gnap.HttpMessageSignatures.AspNetCore
├── AspNetCoreRequestContext     IHttpMessageContext over an incoming request.
├── HttpMessageSignatureMiddleware   401s unsigned/invalid requests, checks
│                                Content-Digest, exposes results as a feature.
└── AddHttpMessageSignatureVerification / UseHttpMessageSignatureVerification
```

## 10. Using it: the client side

The comfortable way — every request through this `HttpClient` is signed
automatically, and bodies get a `Content-Digest`:

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
    NonceLength = 16,
};

using var client = new HttpClient(
    new HttpSignatureDelegatingHandler(signer, new SocketsHttpHandler()));

await client.PostAsync("https://api.example.com/things",
    new StringContent("{\"name\":\"demo\"}", Encoding.UTF8, "application/json"));
```

The manual way — useful when you want to inspect what happens:

```csharp
var result = signer.Sign(request);        // extension on HttpRequestMessage
Console.WriteLine(result.SignatureBase);  // the exact text that was signed
Console.WriteLine(result.SignatureInput); // value of the Signature-Input header
Console.WriteLine(result.Signature);      // value of the Signature header
```

## 11. Using it: the server side

```csharp
using Gnap.HttpMessageSignatures;
using Gnap.HttpMessageSignatures.AspNetCore;

builder.Services.AddHttpMessageSignatureVerification(options =>
{
    // Which public keys do we accept, under which key ids?
    options.KeyResolver = new StaticKeyResolver()
        .Add("my-client", SignatureAlgorithm.Ed25519(clientPublicKey));

    // What must every signature cover, at minimum?
    options.RequiredComponents = [SignatureComponent.Method, SignatureComponent.TargetUri];

    // Reject signatures older than this, even if not expired.
    options.MaxAge = TimeSpan.FromMinutes(10);
});

var app = builder.Build();
app.UseHttpMessageSignatureVerification();   // everything below is protected

app.MapPost("/things", (HttpContext ctx) =>
{
    // Who signed this request?
    var keyId = ctx.Features.Get<IHttpMessageSignatureFeature>()?
        .Result.Signatures[0].Parameters?.KeyId;
    return Results.Ok(new { by = keyId });
});
```

For production, replace `StaticKeyResolver` with your own
`IVerificationKeyResolver` that loads keys from a database, a JWKS endpoint,
or (in later phases of this project) GNAP client registrations.

## 12. Keys and algorithms: which one do I pick?

| Algorithm (RFC name) | Type | Pick it when... |
|---|---|---|
| `ed25519` | asymmetric | **Default choice.** Small keys, fast, no parameter foot-guns. |
| `ecdsa-p256-sha256` | asymmetric | You need broad ecosystem/HSM compatibility. |
| `ecdsa-p384-sha384` | asymmetric | Policy demands a larger curve. |
| `rsa-pss-sha512` | asymmetric | Existing RSA keys/PKI. |
| `rsa-v1_5-sha256` | asymmetric | Legacy interop only. |
| `hmac-sha256` | symmetric | Both sides can share a secret (tests, internal introspection calls). Beware: *anyone who can verify can also sign*. |

Asymmetric means: the client keeps the **private** key, the server only ever
stores the **public** key — a server breach does not let anyone impersonate
clients. That property is why GNAP builds on these signatures.

Loading keys:

```csharp
var rsa           = PemKeyLoader.LoadRsa(pem);      // PKCS#1, PKCS#8, incl. RSASSA-PSS OID
var ecdsa         = PemKeyLoader.LoadEcdsa(pem);    // SEC1 "EC PRIVATE KEY" or PKCS#8
var (pub, priv)   = PemKeyLoader.LoadEd25519(pem);  // PKCS#8 / SubjectPublicKeyInfo
```

(Ed25519 comes from BouncyCastle because .NET 10 still has no standalone
public Ed25519 type — it only appears inside the composite ML-DSA
algorithms; the raw 32-byte keys are exposed so BouncyCastle never leaks
into your code.)

## 13. Try it yourself: the example apps

**One process, everything automatic** — verifies all RFC 9421 Appendix B test
vectors, then runs a live client-vs-server round with a signed, a tampered and
an unsigned request:

```bash
dotnet run --project examples/HttpSignatures.Demo
```

**Two terminals, poke it by hand:**

```bash
# Terminal 1 — a protected resource server on http://localhost:5090
dotnet run --project examples/VerifyingServer

# Terminal 2 — signed requests succeed...
dotnet run --project examples/SigningClient                                     # GET  -> 200
dotnet run --project examples/SigningClient -- POST /api/echo '{"amount": 10}' # POST -> 200

# ...and unsigned ones do not:
curl -i http://localhost:5090/api/hello                                        # -> 401
```

The client prints the full signature base before sending, so you can see with
your own eyes exactly what gets signed. Try editing the body after looking at
the printed `Content-Digest` — the server will reject it.

## 14. Why signatures survive proxies (and when they don't)

Because only *covered* components are signed, these common transformations do
**not** break a signature (RFC 9421 Appendix B.4, all covered by our tests):

- adding new headers (`Via`, `X-Forwarded-For`, `Accept-Language`, ...)
- removing uncovered headers
- reordering *different* headers
- merging duplicate headers onto one line (`Accept: a` + `Accept: b`
  → `Accept: a, b`) — canonicalization produces the same value either way
- adding query parameters, *if* you covered `@query-param` for specific
  parameters rather than the whole `@query`

These **do** break it (on purpose — they change covered content):

- changing the method, path, authority, or a covered header's value
- reordering *duplicate values of the same* header (`Accept: a, b` vs
  `Accept: b, a` are semantically different in HTTP)
- swapping the body when `content-digest` is covered

Rule of thumb: cover what must not change, leave the rest free.

## 15. Security features you get for free

- **Replay resistance:** `created`/`expires`/`MaxAge` bound the time window;
  the optional `nonce` makes each signature unique.
- **Replay prevention (opt-in):** set `VerificationOptions.NonceStore` (or
  `HttpMessageSignatureOptions.NonceStore` for the middleware) and every nonce
  is remembered per `keyid` until the signature's acceptance window
  (`created + MaxAge + ClockSkew`, or `expires + ClockSkew` if earlier) ends —
  a second copy of the same signed message is rejected. Nonces are recorded only
  *after* the cryptographic check passed, so forgeries cannot burn them.
  `RequireNonce = true` rejects signatures without a nonce.
- **Downgrade protection:** an `alg` parameter that contradicts the key's
  registered algorithm is rejected before any crypto runs.
- **Coverage policy:** `RequiredComponents` stops "valid but useless"
  signatures that cover nothing.
- **No verification oracle:** clients see a generic 401; details go to logs.
- **Constant-time comparisons** for HMAC and digest checks (no timing
  side-channel).
- **Body integrity** via the Content-Digest chain (Section 6).

## 16. FAQ and common pitfalls

**Q: My signature covers `content-digest` but the request has no body.**
Signing fails with *"Field 'content-digest' is not present"*. Only cover
`ContentDigest` for requests that have content (see the SigningClient example,
which adds it conditionally).

**Q: The server says the signature is invalid, but I signed correctly!**
Check whether anything *covered* changes en route. Classic case: you sign
`@target-uri` as `http://...` but a proxy upgrades to `https://...`, or the
internal hostname differs from the public one. Cover `@path` + `@query`
instead of the full target URI in such setups, or sign the URL the server
actually sees.

**Q: Clocks differ between client and server.**
That is what `ClockSkew` (default 5 minutes) is for. If your infrastructure
has worse clocks, raise it — or better, fix the clocks.

**Q: Can I have several signatures on one message?**
Yes — labels. Each entry in `Signature-Input`/`Signature` is independent. The
verifier checks all of them (or one specific label if you ask).

**Q: Why is the header called `Signature-Input` and not part of `Signature`?**
Separation lets intermediaries add their own signatures without touching
yours, and lets the verifier know the exact component list and parameters
*before* doing any crypto.

**Q: Is this the same as AWS SigV4 / `Signature` headers from 2012-era drafts?**
Same spirit, but RFC 9421 is the interoperable standard version. Older
"Cavage draft" signatures are *not* wire-compatible.

## 17. Glossary

| Term | Meaning |
|---|---|
| **Signature base** | The canonical multi-line string both sides build and that actually gets signed. |
| **Covered component** | A message part included in the signature base: a header or a derived component. |
| **Derived component** | A `@`-prefixed pseudo-header derived from the message: `@method`, `@path`, `@query`, `@authority`, `@target-uri`, `@scheme`, `@request-target`, `@query-param`, `@status`. |
| **Canonicalization** | The strict cleanup rules (lowercase names, trimmed values, joined duplicates) that make both sides produce identical text. |
| **Label** | The name (`sig1`, `ttrp`, ...) linking one entry in `Signature-Input` to its bytes in `Signature`. |
| **`keyid`** | An opaque name for the key; the verifier maps it to a public key via `IVerificationKeyResolver`. |
| **Structured fields (RFC 8941)** | A strict syntax for HTTP header values (dictionaries, lists, byte sequences) used by both signature headers. |
| **Content-Digest (RFC 9530)** | A header carrying a hash of the body; signing it extends integrity protection to the body. |
| **Nonce** | A random one-time value making each signature unique. |
| **Clock skew** | Tolerated time difference between signer and verifier clocks. |

---

*Next phases of this project build GNAP (RFC 9635) on top of these
signatures: key proofing, grant requests, an authorization server and
resource-server middleware. See the [implementation plan](../output/gnap-dotnet-phases-plan.md).*
