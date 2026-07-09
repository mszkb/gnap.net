# GNAP for Dummies

*A plain-language guide to the Grant Negotiation and Authorization Protocol and
the `Gnap.Core` library.*

This document explains **Phase 1** of gnap.net: the `Gnap.Core` library, which
implements the protocol-neutral building blocks of
**GNAP ([RFC 9635](https://datatracker.ietf.org/doc/rfc9635/))** — keys, key
proofing, the interaction finish hash, and the JSON messages that clients and
servers exchange. No prior GNAP or OAuth knowledge required.

GNAP is built on top of HTTP Message Signatures. If terms like *signature
base*, *covered component* or *Content-Digest* are new to you, read
**[HTTP Message Signatures for Dummies](how-it-works.md)** (Phase 0) first —
this document builds directly on it.

---

## Table of contents

1. [The problem: getting access on someone's behalf](#1-the-problem-getting-access-on-someones-behalf)
2. [The cast: who is who in GNAP](#2-the-cast-who-is-who-in-gnap)
3. [The big picture: one negotiation, four moves](#3-the-big-picture-one-negotiation-four-moves)
4. [Key concept #1: the client *is* its key](#4-key-concept-1-the-client-is-its-key)
5. [Key concept #2: proving you hold the key (httpsig)](#5-key-concept-2-proving-you-hold-the-key-httpsig)
6. [Key concept #3: the messages are just JSON](#6-key-concept-3-the-messages-are-just-json)
7. [Key concept #4: describing access rights](#7-key-concept-4-describing-access-rights)
8. [Key concept #5: the interaction dance and the finish hash](#8-key-concept-5-the-interaction-dance-and-the-finish-hash)
9. [Errors](#9-errors)
10. [Map of the library: which class does what](#10-map-of-the-library-which-class-does-what)
11. [Using it: the signing side](#11-using-it-the-signing-side)
12. [Using it: the validating side](#12-using-it-the-validating-side)
13. [Try it yourself: the example app](#13-try-it-yourself-the-example-app)
14. [Security features you get for free](#14-security-features-you-get-for-free)
15. [What Phase 1 deliberately does *not* do](#15-what-phase-1-deliberately-does-not-do)
16. [FAQ and common pitfalls](#16-faq-and-common-pitfalls)
17. [Glossary](#17-glossary)

---

## 1. The problem: getting access on someone's behalf

A photo-printing app wants to fetch your photos from a photo-hosting service.
Three bad options come to mind:

- You give the app your **password**. Now it can do *everything*, forever, and
  you can only stop it by changing the password everywhere.
- The service hands out long-lived **API keys**. Anyone who steals the key
  *is* the app — keys leak through logs, proxies and copy-paste.
- You build something ad hoc with redirects and tokens and hope you didn't
  reinvent a known vulnerability.

The established answer to this class of problem is *delegated authorization*:
a dedicated **authorization server** asks the resource owner for consent and
issues the app a narrowly scoped **access token**. OAuth 2.0 pioneered this;
**GNAP (RFC 9635)** is the IETF's from-scratch redesign of the idea, with the
lessons of a decade baked in:

- **One negotiation protocol** instead of a zoo of "grant types" and
  extensions. Web apps, native apps, TVs, and headless services all speak the
  same request.
- **Every request is signed with a key.** There is no unauthenticated "public
  client" and no reliance on secrets-in-a-POST-body. Stealing a token is not
  enough; you'd need the client's private key too.
- **Interaction is negotiated.** The client says what it *can* do ("I can
  redirect a browser", "I can display a short code"); the server picks what it
  *will* do. New interaction styles plug in without redesigning the protocol.
- **The client asks for exactly what it wants** with structured access
  descriptions, not a flat space-separated scope string.

## 2. The cast: who is who in GNAP

| Role | Everyday name | What it does |
|---|---|---|
| **Client instance** | the app | Requests access. Holds a private key. One installed copy of an app = one instance. |
| **Authorization server (AS)** | the gatekeeper | Receives grant requests, gets consent, issues tokens. |
| **Resource server (RS)** | the API | Serves protected data to callers presenting a valid access token. |
| **Resource owner (RO)** | the person who can say yes | Authorizes (or denies) the requested access. |
| **End user** | the person at the app | Often the same person as the RO, but not necessarily. |

Keep the client/instance distinction in mind: GNAP identifies *instances* by
their keys, so your phone's copy of an app and your laptop's copy are two
different client instances with two different keys.

## 3. The big picture: one negotiation, four moves

```
 CLIENT INSTANCE                        AUTHORIZATION SERVER            RO
 ---------------                        --------------------           --
 1. POST /gnap  (signed!)      ─────►   parse, verify key proof
    "I want read access to             "interaction needed"
     photos; I can redirect
     the user; here is my key"  ◄─────  2. response:
                                           interact.redirect = URL
                                           interact.finish   = AS nonce
                                           continue.uri + token

 3. send the user to the URL   ─────────────────────────────►  approves
                                                                  │
 4. callback to the client's URI with interact_ref + hash  ◄─────┘
    → client VERIFIES THE HASH (session-fixation protection)

 5. POST continue.uri (signed, with continuation token,
    body: {"interact_ref": ...})  ───►  checks everything again
                                ◄─────  6. response: access_token

 7. call the RS with the token (requests signed with the same key)
```

Two things make this different from what you may know:

- **Every arrow pointing at the AS is a signed HTTP message.** The AS verifies
  a *key proof* on each one (move 1, move 5) and checks it is the *same key*
  throughout. A grant is pinned to a key from its first byte.
- **The negotiation is a loop, not a one-shot.** The response to move 1 or 5
  can grant tokens, demand (more) interaction, say "poll again in 30 seconds",
  or report an error — the same request/response shapes are reused every time.

Phase 1 gives you every building block appearing in this picture: the key
handling (moves 1, 5, 7), the proof creation and validation (1, 5), the hash
verification (4) and the JSON messages (all of them).

## 4. Key concept #1: the client *is* its key

A GNAP client does not have a username and password at the AS. It has a
**key pair**. The public half travels inside the first grant request; the
private half signs every request. The standard wire format for the public half
is a **JSON Web Key (JWK, RFC 7517)**:

```json
{
    "kty": "OKP",
    "crv": "Ed25519",
    "kid": "demo-ed25519",
    "alg": "EdDSA",
    "x": "hZcRQFm_H3QbFv3W59EXz6eKkfGpRPsKlJjhoTLDEng"
}
```

Read it as: *an Ed25519 public key (`x` is the key bytes, base64url), named
`demo-ed25519`, meant for EdDSA signatures*. In this library that is the
[`JsonWebKey`](../src/Gnap.Core/Keys/JsonWebKey.cs) class:

```csharp
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var jwk = JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: "my-key");

jwk.ToPublicKey();            // safe to send: private members stripped
jwk.ComputeThumbprint();      // stable fingerprint of the key (RFC 7638)
jwk.ToSignatureAlgorithm();   // bridges into Phase 0's HTTP signing
```

Three ideas matter here:

- **Thumbprints (RFC 7638).** Hash the key's essential members in a canonical
  order and you get a short, stable fingerprint like
  `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. Same key → same thumbprint,
  regardless of `kid`, `alg` or member order. An AS can use it as a database
  key for "have I seen this client instance before?".
- **The `alg`/`kid` members are load-bearing.** GNAP requires them on keys
  passed by value. The signature's `keyid` parameter must equal the JWK's
  `kid`, and the signing algorithm is *derived from the key* — the wire never
  gets to vote on the algorithm (that would invite downgrade attacks).
- **Keys can also travel by reference.** Instead of the full JWK, a client can
  send an opaque string (`"key": "S-P4XJQ_RYJCRTSU1.63N3E"`) that the AS
  already associates with key material — e.g. from a prior registration.

`JsonWebKey` supports EC (P-256/P-384/P-521), OKP (Ed25519) and RSA keys and
converts to and from the native `ECDsa`/`RSA` types, plus raw byte access for
Ed25519.

## 5. Key concept #2: proving you hold the key (httpsig)

Sending a public key proves nothing — anyone can copy a public key. The
sender must also *prove possession* of the private half, on **every message**.
GNAP calls this a **key proof**, and its main method is `httpsig`: an HTTP
Message Signature (Phase 0) with GNAP-specific rules on top of RFC 9421:

| Rule | Why |
|---|---|
| Must cover `@method` and `@target-uri` | Pin down *what request* this is. |
| Must cover `content-digest` when there is a body | Pin down the body (via the digest chain). |
| Must cover `authorization` when a token is presented | Bind the token to this proof. |
| Must carry `tag="gnap"` | Marks the signature's purpose — a signature made for some other protocol can't be smuggled in. |
| Must carry a fresh `created` timestamp | Old messages die of old age. |
| Should carry a random `nonce` | Enables true replay *prevention* (see below). |
| Must **not** carry an `alg` parameter | The algorithm comes from the key, never from the attacker-writable wire. |

In this library the two sides are
[`HttpSigKeyProofer`](../src/Gnap.Core/Proofing/HttpSigKeyProofer.cs) and
[`HttpSigKeyProofValidator`](../src/Gnap.Core/Proofing/HttpSigKeyProofValidator.cs),
behind the small interfaces `IKeyProofer`/`IKeyProofValidator` (so `mtls`,
`jwsd` and `jws` proofing can be added later without touching callers).

The proofer is one call — it computes the `Content-Digest`, picks the required
covered components, and signs:

```csharp
var request = new HttpRequestMessage(HttpMethod.Post, "https://as.example/gnap")
{
    Content = new StringContent(grantRequestJson, Encoding.UTF8, "application/json"),
};
await HttpSigKeyProofer.FromJwk(privateJwk).AddProofAsync(request);
// request now carries Content-Digest, Signature-Input and Signature
```

The validator re-checks *all* of the rules above and one more thing the RFC
asks servers to do: it remembers nonces. A signature — even a perfectly valid
one — presented twice is an attack:

```csharp
var validator = new HttpSigKeyProofValidator
{
    NonceStore = new InMemoryNonceStore(),   // replay protection
    ExpectedKeyId = clientJwk.Kid,
};

var result = await validator.ValidateAsync(new KeyProofContext
{
    Message = new HttpRequestMessageContext(request),  // or AspNetCoreRequestContext
    Key = clientJwk.ToSignatureAlgorithm(),
    Content = bodyBytes,
});

if (!result.Succeeded)
{
    logger.LogWarning("proof rejected: {Reason}", result.FailureReason);
    // answer the client generically — do not echo the reason
}
```

## 6. Key concept #3: the messages are just JSON

A grant request is a single JSON object POSTed to the AS's *grant endpoint*.
Here is a realistic one, built entirely from Phase 1 model classes:

```json
{
    "access_token": {
        "access": [
            { "type": "photo-api", "actions": ["read"], "datatypes": ["images"] },
            "dolphin-metadata"
        ]
    },
    "client": {
        "key": { "proof": "httpsig", "jwk": { "kty": "OKP", "crv": "Ed25519", "...": "..." } },
        "display": { "name": "My Printing App" }
    },
    "interact": {
        "start": ["redirect"],
        "finish": { "method": "redirect", "uri": "https://app.example/return/123", "nonce": "VJLO6A4CATR0KRO" }
    },
    "subject": { "sub_id_formats": ["opaque"] }
}
```

The response reuses the same vocabulary — tokens, interaction offers, a
continuation handle, subject information, or an error.

RFC 9635's JSON has two habits that make naive (de)serializers fall over, and
handling them correctly is half the value of these models:

- **Many fields are "reference OR object".** `"client"` may be a full object
  *or* the string `"client-541-ab"` (an instance ID the AS already knows).
  The same goes for keys, users, access rights, proof methods and errors. The
  model classes expose this as a `Reference` property next to the structured
  properties, plus an `IsReference` flag — one C# type per field, either form
  on the wire.
- **`access_token` is "object OR array".** Requesting one token? Send an
  object. Requesting several? Send an array (and label each). The models give
  you `IList<AccessTokenRequest>` either way; a one-element list serializes
  back to the object form, exactly as the RFC intends.

Everything round-trips through
[`GnapJson`](../src/Gnap.Core/Json/GnapJson.cs) /
[`GnapJsonContext`](../src/Gnap.Core/Json/GnapJson.cs), a **source-generated**
`System.Text.Json` context: no reflection, trimming- and AOT-safe. Unknown
fields are not dropped — they are captured into `AdditionalFields`
dictionaries and written back out, so a client built today survives protocol
extensions registered tomorrow.

```csharp
var request = GnapJson.DeserializeGrantRequest(json);
var wire    = GnapJson.Serialize(request);   // semantically identical JSON
```

## 7. Key concept #4: describing access rights

Where OAuth has `scope=photos.read photos.write`, GNAP has an `access` array.
Each element is either a **string reference** the AS understands
(`"dolphin-metadata"`) or a **structured object**:

```json
{
    "type": "photo-api",
    "actions": ["read", "write"],
    "locations": ["https://server.example.net/"],
    "datatypes": ["metadata", "images"],
    "identifier": "album-1234",
    "privileges": ["admin"]
}
```

- `type` is mandatory and defines what the other fields mean; everything else
  is a common vocabulary APIs may reuse.
- One object means the *cross product* of its fields (all actions × all
  locations × all datatypes). Want "read images here, delete metadata there"?
  Use two objects — the array is a union.
- APIs can add their own fields (`"currency": "USD"`); the
  [`AccessRight`](../src/Gnap.Core/Models/AccessRight.cs) model preserves them
  in `AdditionalFields`.

The same structure appears in the token response, describing what the token
*actually* grants — which may be less than you asked for.

## 8. Key concept #5: the interaction dance and the finish hash

When the AS needs a human decision it returns interaction instructions —
whichever of the client's offered modes it picked:

```json
{
    "interact": {
        "redirect": "https://as.example/interact/4CF492MLVMSW9MKMXKHQ",
        "finish": "MBDOFXG4Y5CVJCX821LH"
    },
    "continue": {
        "uri": "https://as.example/continue",
        "wait": 30,
        "access_token": { "value": "80UPRY5NM33OMUKMKSKU" }
    }
}
```

The client sends the user to the `redirect` URL. After the RO approves, the AS
sends the user's browser back to the client's `finish.uri` with two query
parameters: an **`interact_ref`** (one-time-use ticket for continuing the
grant) and a **`hash`**.

That hash is the underrated hero of the flow. It is computed — by both sides
independently — over four values joined by newlines:

```
client nonce   (from the client's original request)
AS nonce       (from the AS's response, the "finish" value)
interact_ref   (from the callback itself)
grant endpoint URI (the exact URL the client originally called)
```

hashed (sha-256 by default) and base64url-encoded. **The client MUST verify
it before using the `interact_ref`.** Why? The incoming callback is just a
browser request — *anyone* can aim a browser at your callback URI. An attacker
who starts their *own* grant and tricks your session into finishing it (a
session-fixation attack) will present an `interact_ref` whose hash cannot
match *your* client nonce. One line of verification kills the whole attack
family:

```csharp
var ok = InteractionFinishHash.Verify(
    receivedHash, clientNonce, asNonce, receivedInteractRef,
    "https://as.example/gnap");
if (!ok) { /* reject the callback, do NOT continue the grant */ }
```

[`InteractionFinishHash`](../src/Gnap.Core/InteractionFinishHash.cs) is
verified against the RFC's own test vectors and compares in constant time.

With the hash verified, the client POSTs `{"interact_ref": "..."}` to the
continuation URI — signed with its key, presenting the **continuation access
token** from the `continue` object in the `Authorization: GNAP ...` header
(which the signature then covers). If all checks pass, *this* response finally
carries the access token.

## 9. Errors

Errors are data, not prose. The `error` field is either a bare code string or
an object with a code and a developer-facing description:

```json
{ "error": "user_denied" }
{ "error": { "code": "too_fast", "description": "wait means wait" } }
```

Both forms parse into the same
[`GnapError`](../src/Gnap.Core/Models/GnapError.cs) model.
[`GnapErrorCode`](../src/Gnap.Core/Models/GnapError.cs) ships all thirteen
registered codes (`invalid_request`, `invalid_client`, `user_denied`,
`too_fast`, `unknown_interaction`, ...) as typed constants while remaining an
open string wrapper — extension codes round-trip instead of crashing the
parser. Note that an error response can still include a `continue` object:
"that didn't work, but you may adjust your request and try again".

## 10. Map of the library: which class does what

```
Gnap.Core                                (depends only on Gnap.HttpMessageSignatures)
│
├── Keys/
│   ├── JsonWebKey               JWK parse/serialize (EC, OKP/Ed25519, RSA),
│   │                            RFC 7638 thumbprints, conversion to ECDsa/RSA
│   │                            and to Phase 0's SignatureAlgorithm.
│   ├── GnapKey                  The "key" field: reference string or
│   │                            { proof, jwk, cert, cert#S256 }.
│   └── ProofMethod              "httpsig" as a string or an object with
│                                parameters. Constants in ProofMethod.Methods.
│
├── Proofing/
│   ├── IKeyProofer              Sign an outgoing request  (client side).
│   ├── IKeyProofValidator       Validate a received proof (server side).
│   ├── HttpSigKeyProofer        httpsig implementation over Phase 0's signer.
│   ├── HttpSigKeyProofValidator httpsig validation: coverage, tag, created
│   │                            window, keyid, Content-Digest, nonce replay.
│   └── INonceStore              Replay memory. InMemoryNonceStore included;
│                                implement it over Redis/DB for clusters.
│
├── InteractionFinishHash        Compute/Verify the Section 4.2.3 hash
│                                (sha-256 default; sha-384/512; sha3-* where
│                                the platform supports them).
│
├── Models/                      The RFC 9635 §2–§8 message vocabulary:
│   ├── GrantRequest / GrantResponse / ContinueRequest
│   ├── AccessTokenRequest / AccessTokenResponse / TokenManagement
│   ├── AccessRight              string-or-object, extension fields preserved
│   ├── ClientInstance / ClientDisplay
│   ├── RequestUser / SubjectRequest / SubjectResponse
│   │       / SubjectIdentifier (RFC 9493) / SubjectAssertion
│   ├── InteractRequest / StartMode / InteractFinish / InteractHints
│   │       / InteractResponse / UserCodeUri
│   └── GnapError / GnapErrorCode
│
├── Json/
│   ├── GnapJsonContext          Source-generated serializer context (no
│   │                            reflection; AOT/trimming safe).
│   └── GnapJson                 Serialize/Deserialize helpers for the
│                                top-level messages.
│
├── GnapConstants                "GNAP" auth scheme, the "gnap" signature tag.
└── GnapException                Thrown for malformed keys/unsupported formats.
```

## 11. Using it: the signing side

This is what a client will do in Phase 2 — you can already do it by hand:

```csharp
using Gnap.Core;
using Gnap.Core.Json;
using Gnap.Core.Keys;
using Gnap.Core.Models;
using Gnap.Core.Proofing;

// One key pair per client instance, created once and stored safely.
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var key = JsonWebKey.FromECDsa(ecdsa, includePrivateKey: true, keyId: "my-app-1");

var grantRequest = new GrantRequest
{
    AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("photos-read")] }],
    Client = new ClientInstance
    {
        Key = GnapKey.ForHttpSig(key),          // public part only, proof = "httpsig"
        Display = new ClientDisplay { Name = "My Printing App" },
    },
    Interact = new InteractRequest
    {
        Start = [new StartMode(StartModes.Redirect)],
        Finish = new InteractFinish
        {
            Method = FinishMethods.Redirect,
            Uri = "https://app.example/return/123",
            Nonce = myFreshRandomNonce,
        },
    },
};

var request = new HttpRequestMessage(HttpMethod.Post, "https://as.example/gnap")
{
    Content = new StringContent(GnapJson.Serialize(grantRequest),
        Encoding.UTF8, GnapConstants.MediaType),
};
await HttpSigKeyProofer.FromJwk(key).AddProofAsync(request);

var response = await httpClient.SendAsync(request);
var grant = GnapJson.DeserializeGrantResponse(await response.Content.ReadAsStringAsync());
```

## 12. Using it: the validating side

This is the kernel of what the AS framework will do in Phase 3:

```csharp
// Shared across requests: replay memory.
var nonces = new InMemoryNonceStore();

app.MapPost("/gnap", async (HttpContext context) =>
{
    // 1. Read the body and parse the grant request.
    using var buffer = new MemoryStream();
    await context.Request.Body.CopyToAsync(buffer);
    var body = buffer.ToArray();
    var grantRequest = JsonSerializer.Deserialize(body, GnapJsonContext.Default.GrantRequest);

    // 2. The client's key arrives inside the request itself.
    var jwk = grantRequest?.Client?.Key?.Jwk;
    if (jwk is null) { /* -> error invalid_client */ }

    // 3. Validate the key proof against exactly that key.
    var validator = new HttpSigKeyProofValidator
    {
        NonceStore = nonces,
        RequireNonce = true,
        ExpectedKeyId = jwk.Kid,
    };
    var proof = await validator.ValidateAsync(new KeyProofContext
    {
        Message = new AspNetCoreRequestContext(context.Request),
        Key = jwk.ToSignatureAlgorithm(),
        Content = body,
    });
    if (!proof.Succeeded) { /* log proof.FailureReason, answer generically */ }

    // 4. Now — and only now — look at what the client is asking for.
    //    (Policy, consent, token issuance: Phase 3.)
});
```

The order matters: *authenticate the message first, interpret it second.* The
only part of the body you touch before proof validation is the key itself —
and the proof check is precisely what makes that key trustworthy.

## 13. Try it yourself: the example app

One process, five guided parts — keys, models, proofing, hash, and a live
round trip against an in-process miniature AS built from Phase 1 pieces alone:

```bash
dotnet run --project examples/GnapCore.Demo              # everything
dotnet run --project examples/GnapCore.Demo -- keys      # JWKs & thumbprints
dotnet run --project examples/GnapCore.Demo -- models    # request/response JSON
dotnet run --project examples/GnapCore.Demo -- proofing  # sign + validate + attacks
dotnet run --project examples/GnapCore.Demo -- hash      # finish hash vectors
dotnet run --project examples/GnapCore.Demo -- live      # full grant negotiation
```

The `live` part is the whole Section 3 picture in miniature: a signed grant
request is accepted; a byte-identical **replay** of it is rejected (nonce
store); a **tampered body** under the original signature is rejected
(Content-Digest); the **finish hash** verifies and a forged `interact_ref`
does not; and a signed **continuation** presenting the bound continuation
token returns the access token. The mini AS prints *why* it rejects things to
the console — the HTTP responses stay deliberately vague.

## 14. Security features you get for free

- **Replay prevention, not just resistance.** Phase 0 bounds the time window;
  Phase 1's `INonceStore` remembers nonces, so even a fresh signature can only
  be spent once.
- **No algorithm negotiation.** The signing algorithm is derived from the key
  (`JsonWebKey.ToSignatureAlgorithm()`); an advertised `alg` parameter on the
  wire is rejected outright.
- **Purpose binding.** Only signatures tagged `gnap` are accepted — a valid
  signature made for another protocol cannot be replayed into GNAP.
- **Session-fixation defense** via the mandatory finish hash check, in
  constant time.
- **No verification oracle.** Validators return a diagnostic `FailureReason`
  for your logs; nothing in the design encourages echoing it to callers.
- **Forward compatibility without laxity.** Unknown JSON members are
  preserved; malformed unions (a number where a string-or-object belongs, an
  error object without a code) fail loudly.
- **No private keys on the wire.** `GnapKey.ForHttpSig()` strips private JWK
  members; symmetric keys can only be referenced, never embedded.

## 15. What Phase 1 deliberately does *not* do

`Gnap.Core` is the vocabulary and the cryptography, not the conversation:

- It does **not** run the client-side state machine (discovery, polling with
  `wait`, token rotation) — that is **Phase 2, `Gnap.Client`**.
- It does **not** decide policy, render consent screens, store grants or issue
  tokens — that is **Phase 3**, the AS framework in `Gnap.AspNetCore`.
- It does **not** protect your API routes with `Authorization: GNAP` handling
  — that is **Phase 4**, the resource server middleware.
- `mtls`, `jwsd` and `jws` key proofing methods are modeled (`ProofMethod`)
  but only `httpsig` is implemented so far.

See the [implementation plan](../output/gnap-dotnet-phases-plan.md) for the
full roadmap.

## 16. FAQ and common pitfalls

**Q: How is this different from OAuth 2.0 in one sentence?**
One signed, extensible negotiation replaces many grant types, and tokens are
bound to client keys by default instead of being bearer secrets.

**Q: Do I need to register my app at the AS first?**
Not necessarily. A client can show up with a brand-new key; the AS decides
what unknown keys may do (trust-on-first-use, restricted access, or flat
denial with `invalid_client`).

**Q: Why did validation fail with "the nonce was already used"?**
That is the replay protection working. Every request needs a *fresh*
signature — sign each `HttpRequestMessage` right before sending it, and never
reuse a signed message object.

**Q: My AS rejects the proof with a keyid mismatch.**
The signature's `keyid` must equal the JWK's `kid`. `HttpSigKeyProofer.FromJwk`
does this automatically; if you construct the proofer manually, pass the same
identifier.

**Q: Which hash method should I use for `finish.hash_method`?**
Leave it out. The default (`sha-256`) is universally supported; only set it if
you have an ecosystem requirement, and check
`InteractionFinishHash.IsSupported(...)` for the SHA-3 family.

**Q: Why `IList<AccessTokenRequest>` when I only ever request one token?**
Because the wire format is "object or array". A one-element list serializes
as the object form, so the common case looks exactly like the RFC's examples.

**Q: Where do bearer tokens fit in?**
Request one with the `bearer` flag. But the GNAP default — tokens bound to
your key — means a stolen token is useless without the key. Only go bearer
when you must.

**Q: Can the AS bind a token to a different key than mine?**
Yes; the token response's `key` field then names it. The model exposes
`IsBoundToClientKey` so you can tell the cases apart, and clients must reject
tokens that carry both the `bearer` flag and a `key`.

## 17. Glossary

| Term | Meaning |
|---|---|
| **Grant** | One negotiation for access, from first request to tokens (or denial). Lives at the AS with a state (processing, pending, approved, finalized, revoked). |
| **Grant endpoint** | The AS URL where negotiations start; also the AS's identity string in the finish hash. |
| **Client instance** | One installation of client software, identified by its key. |
| **Key proof** | Evidence, attached to a message, that the sender holds a key's private half. Methods: `httpsig`, `mtls`, `jwsd`, `jws`. |
| **JWK / thumbprint** | JSON wire format for keys / canonical SHA-256 fingerprint of a key (RFC 7638). |
| **Access right** | One element of the `access` array: a reference string or a typed object (`type`, `actions`, `locations`, ...). |
| **Interaction start / finish** | How the user gets *to* the AS (redirect, app, user_code, ...) / how the client learns it is over (redirect or push callback). |
| **Finish hash** | Hash over client nonce, AS nonce, `interact_ref` and grant endpoint that the client must verify before continuing. |
| **`interact_ref`** | One-time-use reference presented on continuation after interaction. |
| **Continuation** | Follow-up request to the `continue.uri`, signed and carrying the continuation access token. |
| **Continuation access token** | Key-bound token from the `continue` object; only good for continuing this grant. |
| **Bearer vs. key-bound token** | Bearer: possession suffices. Key-bound (default): must be presented in a request signed with the bound key. |
| **Subject identifier** | A structured "who" (RFC 9493): `opaque`, `email`, `iss_sub`, `phone_number`, `did`, ... |
| **Instance ID** | Opaque shorthand the AS may issue so a client can say `"client": "client-541-ab"` next time. |
| **Nonce store** | Server-side memory of seen signature nonces; turns replay resistance into replay prevention. |

---

*Previous: [HTTP Message Signatures for Dummies](how-it-works.md) (Phase 0).
Next up: Phase 2 builds the full client library on top of these primitives —
see the [implementation plan](../output/gnap-dotnet-phases-plan.md).*
