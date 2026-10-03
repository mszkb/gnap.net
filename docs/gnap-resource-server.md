# Protecting an API with GNAP (Gnap.AspNetCore resource server)

`Gnap.AspNetCore` also contains the **resource server** (RS) side of GNAP
([RFC 9635](https://datatracker.ietf.org/doc/rfc9635/) §7.2, §9.1) and its connection
to the authorization server ([RFC 9767](https://datatracker.ietf.org/doc/rfc9767/)):
an ASP.NET Core authentication handler that accepts `Authorization: GNAP <token>`,
verifies the token and — for key-bound tokens — the request signature, and
authorization policies that map the token's rights of access to endpoints.
New to the vocabulary? Read [GNAP for Dummies](gnap-for-dummies.md) first; the AS
side is described in [Running a GNAP authorization server](gnap-authorization-server.md).

## Contents

1. [The 30-second version](#1-the-30-second-version)
2. [What happens on every request](#2-what-happens-on-every-request)
3. [Validating tokens: introspection, token store, JWT](#3-validating-tokens-introspection-token-store-jwt)
4. [Authorization: `RequireGnapAccess`](#4-authorization-requiregnapaccess)
5. [Errors and the `WWW-Authenticate` challenge](#5-errors-and-the-www-authenticate-challenge)
6. [Talking to the AS (RFC 9767)](#6-talking-to-the-as-rfc-9767)
7. [Security properties](#7-security-properties)
8. [Options](#8-options)
9. [What is not covered (yet)](#9-what-is-not-covered-yet)

## 1. The 30-second version

Register the RS at the AS (identifier + public key, see the AS guide §8), then:

```csharp
using Gnap.AspNetCore.ResourceServer;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddGnapResourceServer(options =>
{
    options.AuthorizationServer = new Uri("https://as.example");   // discovery: /.well-known/gnap-as-rs
    options.ResourceServerId = "photo-rs";                          // as registered at the AS
    options.SigningKey = rsPrivateJwk;                              // signs introspection requests
    options.ResourceSet = [new AccessRight { Type = "photo-api", Actions = ["read"] }];
});

var app = builder.Build();
app.UseGnapResourceServer();                                        // UseAuthentication + UseAuthorization

app.MapGet("/photos", (HttpContext context) => $"photos of {context.GetGnapToken()!.Subject}")
   .RequireGnapAccess("photo-api", "read");
app.Run();
```

A `Gnap.Client` application calls it with `GnapAccessTokenHandler`, which presents
the token and signs every request with the bound key:

```csharp
var api = new HttpClient(new GnapAccessTokenHandler(gnapClient.CreateTokenSource(token), new HttpClientHandler()));
var photos = await api.GetStringAsync("https://rs.example/photos");
```

## 2. What happens on every request

1. `Authorization: GNAP <token>` is parsed (RFC 9635 §7.2). Other schemes and a
   missing header leave the request unauthenticated (→ 401 on protected endpoints).
2. The token is resolved by the `IGnapTokenValidator` (section 3). Unknown, inactive,
   revoked or forged tokens are rejected; so are expired ones (`exp` ≤ now).
3. **Key-bound tokens** (the default at the AS) must come with an `httpsig` key proof
   (RFC 9635 §7.3.1) by the key bound to the token: a signature with `tag="gnap"`
   covering `@method`, `@target-uri`, `authorization` and, for requests with a body,
   `content-digest` — whose digest is checked against the body (the body is buffered
   up to `MaxRequestBodySize` and rewound for your endpoint). The signature must be
   fresh (`SignatureMaxAge`, `SignatureClockSkew`) and its `nonce` unseen
   (`RequireSignatureNonce`, replay protection). There is no fallback: a key-bound
   token without a valid signature is **always** rejected, and a token without a key
   counts as bearer only when the AS explicitly flagged it `bearer`.
4. **Bearer tokens** are accepted only with `AllowBearerTokens = true`.
5. On success the request gets a `ClaimsPrincipal` (scheme `GNAP`; claims `sub`,
   `instance_id`, `iss` and one `gnap_access` claim per right, as JSON) and an
   `IGnapTokenFeature` — `context.GetGnapToken()` returns the `GnapTokenInfo`
   (access, key, flags, `iat`, `exp`, issuer, subject, instance id).

## 3. Validating tokens: introspection, token store, JWT

`AddGnapResourceServer` returns a builder that selects the `IGnapTokenValidator`:

| Mode | Call | Works with | Revocation visible | AS round trip |
|---|---|---|---|---|
| Introspection (default) | `.UseIntrospection()` | every token format | after ≤ `IntrospectionCacheDuration` (or at once via `GnapIntrospectionCache.Invalidate`) | on cache miss |
| Co-hosted token store | `.UseLocalTokenStore()` | every format, AS in the same app | immediately | none |
| Self-contained JWT | `.UseJwtTokens(asPublicJwk, issuer)` | `JwtTokenFormat` tokens | **no** — only expiry | none |
| Custom | `.UseTokenValidator<T>()` | anything | — | — |

**Introspection** (RFC 9767 §3.3) posts `{"access_token", "resource_server"}` to the
AS's `introspection_endpoint`, signed with `SigningKey`. Results are cached by the
SHA-256 hash of the token (token values are never stored): active results for
`IntrospectionCacheDuration` (default 1 minute) but never beyond the token's `exp`,
inactive results for `NegativeCacheDuration` (default 10 s); the cache holds at most
`IntrospectionCacheSize` entries. Failed AS calls are not cached. To react to a
revocation at once, call `GnapIntrospectionCache.Invalidate(token)` (the cache is a
DI singleton); `IntrospectionCacheDuration = TimeSpan.Zero` disables caching.

**Local JWT verification** checks the JWS signature with the AS's public key(s)
(`JwtTokenFormat.PublicKey`), `typ: gnap-at+jwt`, the optional expected `iss`, and that
the bound `key` claim matches `cnf.jkt`. Keep JWT lifetimes short if revocation
matters, or use introspection.

The **token store** mode is for an RS hosted in the same application as the AS
(`AddGnapAuthorizationServer`): it reads the AS's `ITokenStore` directly.

## 4. Authorization: `RequireGnapAccess`

```csharp
app.MapGet("/photos", …).RequireGnapAccess("photo-api", "read");         // type + actions
app.MapGet("/album", …).RequireGnapAccess("my-access-reference");         // access reference
app.MapGet("/meta", …).RequireGnapAccess(new GnapAccessRequirement(r => r.Datatypes?.Contains("metadata") is true));
app.MapGet("/whoami", …).RequireGnapToken();                             // any valid token

builder.Services.AddAuthorization(o => o.AddPolicy("photos", p => p.RequireGnapAccess("photo-api", "read")));
```

A `GnapAccessRequirement(typeOrReference, actions, locations)` is met when one right
of the token is the access reference `typeOrReference`, or an object-form right of
that `type` listing all `actions` (and `locations`). Every `RequireGnapAccess` policy
authenticates with the `GNAP` scheme and requires an authenticated user. MVC
controllers can use the named-policy form with `[Authorize(Policy = "photos")]`.

## 5. Errors and the `WWW-Authenticate` challenge

| Situation | Status |
|---|---|
| No token, other scheme, malformed, unknown, inactive, revoked, expired token; missing or invalid signature; bearer token not allowed | **401** |
| Valid token without the required rights | **403** |

Both carry the challenge of RFC 9635 §9.1:

```
WWW-Authenticate: GNAP as_uri="https://as.example/gnap/tx", access="<reference>"
```

`as_uri` is `GrantEndpoint`, or the `grant_request_endpoint` discovered from the AS.
`access` is `AccessReference`, or — when only `ResourceSet` is configured — the
reference the RS obtained by registering that set at the AS (section 6). Clients such
as `Gnap.Client` read it with `GnapResourceChallenge.TryParse` and can request the
reference verbatim. Response bodies are empty; the concrete reason is logged only.

## 6. Talking to the AS (RFC 9767)

`GnapAsRsClient` (a DI singleton, `HttpClient` named
`GnapResourceServerDefaults.BackchannelHttpClientName`) implements the RS ↔ AS
connection; every call except discovery is signed with `SigningKey` and names the RS
by `ResourceServerId`:

* `GetMetadataAsync()` — the AS's `/.well-known/gnap-as-rs` (grant, introspection and
  resource registration endpoints, `token_formats_supported`, `key_proofs_supported`),
  fetched once.
* `RegisterResourceSetAsync(access)` — RFC 9767 §3.4, returns the `resource_reference`.
  Done automatically (once, retried on failure) for `ResourceSet` when the first
  challenge is built.
* `IntrospectAsync(token, access?)` — RFC 9767 §3.3, used by the introspection validator.

Explicit `GrantEndpoint`, `IntrospectionEndpoint` and `ResourceRegistrationEndpoint`
options skip discovery.

## 7. Security properties

* Key-bound tokens are never accepted without a valid key proof by the bound key
  (wrong key, stolen token signed by another client, tampered body or digest, swapped
  `Authorization` field, stale or nonce-less signature, replay — all 401; tested for
  every validation mode).
* Keys bound by reference cannot be verified by the RS and are rejected.
* A token is bearer only if the AS flagged it `bearer` *and* bound no key.
* Rejections use one generic response; the reason (signature failure, inactive,
  expired, …) goes to the log only.
* The nonce replay store defaults to an in-memory store; with several RS instances
  register a shared `INonceStore` (`Gnap.HttpMessageSignatures`).

## 8. Options

| Option | Default | Meaning |
|---|---|---|
| `AuthorizationServer` | — | AS origin for discovery (`/.well-known/gnap-as-rs`) |
| `GrantEndpoint` / `IntrospectionEndpoint` / `ResourceRegistrationEndpoint` | discovered | Explicit AS endpoints |
| `ResourceServerId` / `SigningKey` | — | RS identity at the AS and its private JWK |
| `AccessReference` / `ResourceSet` | — | `access` in the challenge, or the set to register for it |
| `AllowBearerTokens` | `false` | Accept bearer tokens |
| `RequireSignatureNonce` | `true` | Signatures must carry a `nonce` |
| `SignatureMaxAge` / `SignatureClockSkew` | 5 min / 5 min | Signature freshness window |
| `MaxRequestBodySize` | 1 MiB | Largest body buffered for digest verification |
| `IntrospectionCacheDuration` / `NegativeCacheDuration` | 1 min / 10 s | Introspection cache lifetimes |
| `IntrospectionCacheSize` | 10 000 | Maximum cached introspection results |
| `TimeProvider` | system clock | For tests |

## 9. What is not covered (yet)

* Proofing methods other than `httpsig` (`mtls`, `jwsd`, `jws`) and keys bound by reference.
* Token audiences, RS-presented keys by value at the AS, and token chaining
  (RFC 9767 §4, downstream tokens).
* Push-based revocation from the AS to the RS (use short cache lifetimes or
  `GnapIntrospectionCache.Invalidate`).
* A JWKS endpoint at the AS: the JWT validator is configured with the AS public key.
