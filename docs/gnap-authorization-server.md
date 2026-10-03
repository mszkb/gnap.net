# Running a GNAP authorization server with Gnap.AspNetCore

`Gnap.AspNetCore` turns any ASP.NET Core application into a GNAP authorization
server (AS, [RFC 9635](https://datatracker.ietf.org/doc/rfc9635/)), including the
RS-facing token introspection of [RFC 9767](https://datatracker.ietf.org/doc/rfc9767/).
The protocol is handled by the library; you decide **who gets what** (the policy),
**where state lives** (the stores) and **what the resource owner sees** (the consent
UI). New to the vocabulary? Read [GNAP for Dummies](gnap-for-dummies.md) first.

## Contents

1. [The 30-second version](#1-the-30-second-version)
2. [Endpoints](#2-endpoints)
3. [Policy: deny by default](#3-policy-deny-by-default)
4. [Interaction and the consent UI](#4-interaction-and-the-consent-ui)
5. [Grant lifecycle](#5-grant-lifecycle)
6. [Tokens](#6-tokens)
7. [Storage](#7-storage)
8. [Introspection for resource servers](#8-introspection-for-resource-servers)
9. [Security properties](#9-security-properties)
10. [Options](#10-options)
11. [What is not covered (yet)](#11-what-is-not-covered-yet)

## 1. The 30-second version

```csharp
using Gnap.AspNetCore.AuthorizationServer;
using Gnap.AspNetCore.AuthorizationServer.Policy;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();                       // your consent UI
builder.Services
    .AddGnapAuthorizationServer()                       // in-memory stores, opaque tokens
    .AddGrantPolicy(_ => GrantDecision.RequireInteraction()); // ask the RO for everything

var app = builder.Build();
app.MapGnapAuthorizationServer();                       // grant endpoint: /gnap/tx
app.MapRazorPages();                                    // /consent, see section 4
app.Run();
```

Any GNAP client — for example `Gnap.Client` with
`GrantEndpoint = https://your-host/gnap/tx` — can now request access. The
[example server](../examples/GnapAuthorizationServer) adds a Razor Pages consent
page and EF Core (SQLite) storage:

```bash
dotnet run --project examples/GnapAuthorizationServer --urls http://localhost:5100
curl -X OPTIONS http://localhost:5100/gnap/tx    # discovery
```

## 2. Endpoints

`MapGnapAuthorizationServer()` maps, below `BasePath` (default `/gnap`):

| Endpoint | RFC | Purpose |
|---|---|---|
| `POST /tx` | 9635 §2 | Grant requests |
| `OPTIONS /tx`, `GET /.well-known/gnap-as-rs` (root) | 9635 §9, 9767 §3.1 | Discovery |
| `POST /continue/{grantId}` | 9635 §5.1, §5.2 | Continue after interaction / poll |
| `DELETE /continue/{grantId}` | 9635 §5.4 | Revoke the grant (and its tokens) |
| `PATCH /continue/{grantId}` | 9635 §5.3 | Grant modification — answered with `invalid_request` (not supported) |
| `GET /interact/{interactionId}` | 9635 §4.1.1 | Redirect start mode: binds the browser, then shows the consent UI |
| `GET`/`POST /device` | 9635 §4.1.2, §4.1.3 | User code entry (`user_code`, `user_code_uri`) |
| `POST /token/{manageId}` | 9635 §6.1 | Token rotation, key rotation (§6.1.2) |
| `DELETE /token/{manageId}` | 9635 §6.2 | Token revocation |
| `POST /introspect` | 9767 §3.3 | Token introspection for resource servers |

All absolute URIs handed out (continuation, interaction, management) are built
from the request's origin, or from `PublicOrigin` when set — set it (or configure
forwarded headers) behind a reverse proxy, because the grant endpoint URI enters
the interaction finish hash.

## 3. Policy: deny by default

Every grant request whose key proof verified is handed to the `IGrantPolicy`:

```csharp
public sealed class MyPolicy : IGrantPolicy
{
    public ValueTask<GrantDecision> EvaluateAsync(GrantPolicyContext context, CancellationToken ct)
    {
        // context.Client: Key, KeyThumbprint, InstanceId, ClassId, Display, IsRegistered
        // context.Request: the access tokens, subject, user and interact requested
        // context.CanInteract: the client offered a start mode this AS supports
        if (context.Client.IsRegistered && OnlyReads(context.Request))
        {
            return ValueTask.FromResult(GrantDecision.Approve());
        }

        return ValueTask.FromResult(GrantDecision.RequireInteraction());
    }
}

builder.Services.AddGnapAuthorizationServer().AddGrantPolicy<MyPolicy>();
```

| Decision | Effect |
|---|---|
| `GrantDecision.Approve(approval?)` | Tokens are issued in the grant response, no interaction |
| `GrantDecision.RequireInteraction()` | The RO decides on the consent UI; if the client cannot interact the request is denied (`request_denied`) |
| `GrantDecision.Deny(code?)` | Error response, `request_denied` by default |

Without a registered policy the AS uses `DenyAllGrantPolicy`: **nothing** is granted
until you say so. A `GrantApproval` can narrow what is granted (`Access`, one list
per requested token), release subject information (`Subject`), record the
`ResourceOwner` and shorten the `AccessTokenLifetime`.

## 4. Interaction and the consent UI

For `RequireInteraction`, the grant response carries the interaction modes the
client asked for — `redirect` (a URI to `/interact/{id}`), `user_code` and
`user_code_uri` (an `ABCD-EFGH` code to enter at `/device`) — plus the AS `finish`
nonce when the client wants a finish callback.

When the browser arrives, the AS **binds the interaction to that browser** with an
HttpOnly session cookie (and consumes the user code), then hands over to the
`IGnapInteractionPage`. The default page redirects to `ConsentPath` (default
`/consent`) with `?interaction={id}`. Your consent page uses
`IGnapInteractionService`:

```csharp
public sealed class ConsentModel(IGnapInteractionService interactions) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Interaction { get; set; }
    public GnapInteractionContext? Pending { get; private set; }

    public async Task OnGetAsync() =>
        Pending = await interactions.GetInteractionAsync(HttpContext, Interaction!); // null: unknown/expired/other browser

    public async Task<IActionResult> OnPostApproveAsync()
    {
        var done = await interactions.ApproveAsync(HttpContext, Interaction!,
            new GrantApproval { ResourceOwner = User.Identity!.Name });
        return done.RedirectUri is { } back ? Redirect(back.AbsoluteUri) : RedirectToPage("Done");
    }

    public async Task<IActionResult> OnPostDenyAsync() { /* interactions.DenyAsync(...) */ }
}
```

Approving or denying finishes the interaction (RFC 9635 §4.2): for the `redirect`
finish method `RedirectUri` is the client's callback with `hash` and `interact_ref`;
for `push` the AS has POSTed them to the client (via the named `HttpClient`
`GnapAuthorizationServerOptions.PushHttpClientName`); without a finish method the
client learns the result by polling. A denial is reported to the client as
`user_denied` on its next continuation. The complete reference page is
[`examples/GnapAuthorizationServer/Pages/Consent.cshtml`](../examples/GnapAuthorizationServer/Pages/Consent.cshtml).
Replace `IGnapInteractionPage` (`AddInteractionPage<T>()`) to change where the
browser goes, the user code form or the error page.

## 5. Grant lifecycle

Grants follow the states of RFC 9635 §1.5; `GrantRecord.TransitionTo` enforces the
table, so illegal moves (e.g. issuing tokens twice) throw instead of happening:

```
Processing ──► Pending ──► Approved ──► Finalized
     │            │           │             │
     └────────────┴───────────┴─────────────┴──► Revoked (denied or revoked; terminal)
Processing ──► Approved (policy approval)
```

Continuation (`POST /continue/{grantId}`) requires the grant's **current**
continuation access token (rotated on every response) and a signature by the
**same key** that made the grant request. Polling earlier than `wait` (default 5 s)
gives `too_fast`. With a finish method, tokens are only released against the
`interact_ref` from the callback, which is single-use: a wrong reference gives
`invalid_interaction` and leaves the grant untouched, a reused one gives
`unknown_interaction`. Finalized grants keep a continuation token for
`FinalizedGrantLifetime` so the client can revoke them (`DELETE`), which revokes
all their tokens.

## 6. Tokens

* **Key-bound by default.** Tokens are bound to the client instance's key; bearer
  tokens (`"flags": ["bearer"]`) are refused with `invalid_flag` unless
  `AllowBearerTokens` is set.
* **Several tokens per grant.** Labeled `access_token` arrays get one token per label.
* **Formats.** `ITokenFormat` creates the value; the default `OpaqueTokenFormat` is
  256 random bits. `JwtTokenFormat(signingJwk)` issues signed JWTs
  (`typ: gnap-at+jwt`, claims `iss`, `jti`, `iat`, `exp`, `access`, `sub`,
  `instance_id`, `cnf.jkt` for key-bound tokens). Every token is also recorded in the
  token store, so revocation and introspection work for all formats.
* **Management.** Each token carries a `manage` URI and management token (unless
  `EnableTokenManagement = false`): `POST` rotates it (single-use: the old value is
  revoked), `POST` with a `key` rotates the bound key — the request must be signed
  by the current **and** the new key, the new signature covering the old one —
  and `DELETE` revokes it.
* **Instance identifiers.** Clients that present their key by value get an
  `instance_id` on their first finalized grant (`IssueInstanceIds`), registered in
  the `IClientKeyStore`; afterwards `context.Client.IsRegistered` is true for them.

## 7. Storage

| Interface | Holds | Default |
|---|---|---|
| `IGrantStore` | Grants (`GrantRecord`) | `InMemoryGrantStore` |
| `ITokenStore` | Issued tokens (`TokenRecord`) | `InMemoryTokenStore` |
| `IClientKeyStore` | Client instances (`instance_id`) and key references | `InMemoryClientKeyStore` |
| `IResourceServerStore` | Resource servers allowed to introspect | `InMemoryResourceServerStore` |

All defaults are registered with `TryAdd` (register your own first, or replace them
with `AddGrantStore<T>()`, `AddTokenStore<T>()`, `AddClientKeyStore<T>()`,
`AddResourceServerStore<T>()` — scoped — or the instance overloads). Secrets are
stored only as SHA-256 hashes: token values, management tokens, continuation
tokens, interaction references and session bindings.

`IGrantStore.TryUpdateAsync` must be an atomic compare-and-swap on
`GrantRecord.Version`; it is what keeps `interact_ref`, user codes and continuation
tokens single-use under concurrency. `ITokenStore.RevokeAsync` must report whether
*this* call revoked the token (single-use rotation). The
[EF Core example](../examples/GnapAuthorizationServer/Storage/EfCoreStores.cs)
shows both with `ExecuteUpdateAsync` and a version column.

For several AS instances, also register a shared `INonceStore`
(`Gnap.HttpMessageSignatures`) — the AS uses it for signature replay protection
and falls back to an in-memory store.

## 8. Introspection for resource servers

A resource server registers with an identifier and key:

```csharp
var resourceServers = new InMemoryResourceServerStore()
    .Add(new ResourceServerRegistration { Id = "photo-rs", Key = GnapKey.ForHttpSig(rsPublicJwk) });
builder.Services.AddGnapAuthorizationServer().AddResourceServerStore(resourceServers);
```

and POSTs, signed with that key (`httpsig`), to `/gnap/introspect`:

```json
{ "access_token": "…", "resource_server": "photo-rs", "proof": "httpsig",
  "access": [ { "type": "photo-api", "actions": ["read"] } ] }
```

An active token is described with `active`, `access`, `key` (key-bound) or
`flags: ["bearer"]`, `iat`, `exp`, `iss`, `instance_id` and `sub`. Unknown,
expired and revoked tokens, a `proof` that does not match the token's binding, or
`access` the token does not carry all give exactly `{"active":false}`.
Unauthenticated callers get `invalid_client`. Phase 4 builds the RS middleware on
top of this.

## 9. Security properties

* Every request to the AS (grant, continuation, management, introspection) must
  carry a valid `httpsig` key proof (RFC 9635 §7.3.1) with a fresh `created`
  (`SignatureMaxAge`, `SignatureClockSkew`) and, by default, a `nonce` that is
  accepted only once (`RequireSignatureNonce`).
* JWKs with private key material are rejected; keys by reference and instance
  identifiers are resolved through the `IClientKeyStore`.
* Error responses use fixed descriptions per error code; the concrete reason
  (bad signature, stale `created`, unknown grant, rotated token, …) goes to the
  log only. Unknown grants, foreign, rotated and expired continuation tokens are
  indistinguishable.
* Interactions are bound to the first browser that opens them; user codes and
  interaction references are single-use; interactions expire after
  `InteractionLifetime`.
* The `push` finish method makes the AS POST to a URI chosen by the client. Restrict
  it (e.g. with a policy that checks `interact.finish.uri`) if that matters in your
  network.

## 10. Options

| Option | Default | Meaning |
|---|---|---|
| `BasePath` | `/gnap` | Prefix of all endpoints |
| `PublicOrigin` | from request | Origin of all absolute URIs |
| `AccessTokenLifetime` | 1 h | Token lifetime unless the approval says otherwise |
| `InteractionLifetime` | 10 min | Validity of interaction URIs and user codes |
| `FinalizedGrantLifetime` | 1 h | Validity of the continuation token after finalization |
| `ContinueWaitSeconds` | 5 | `wait` returned with continuation information |
| `AllowBearerTokens` | `false` | Whether `bearer` tokens may be requested |
| `EnableTokenManagement` / `AllowKeyRotation` | `true` / `true` | Token management API and key rotation |
| `IssueInstanceIds` | `true` | Assign `instance_id`s to by-value clients |
| `EnableIntrospection` | `true` | Map the introspection endpoint |
| `RequireSignatureNonce` | `true` | Signatures must carry a `nonce` |
| `SignatureMaxAge` / `SignatureClockSkew` | 5 min / 5 min | Signature freshness window |
| `MaxRequestBodySize` | 64 KiB | Largest accepted request body |
| `ConsentPath` | `/consent` | Where the default interaction page sends the browser |
| `SubjectIdFormatsSupported` | none | Advertised in discovery |
| `TimeProvider` | system clock | For tests |

## 11. What is not covered (yet)

* Grant modification (`PATCH`, RFC 9635 §5.3) — answered with `invalid_request`.
* The `app` start mode and proofing methods other than `httpsig` (`mtls`, `jwsd`, `jws`).
* RS-first resource registration (RFC 9767 §3.4) and token audiences.
* Attempt limiting for user code entry (codes have ~34 bits of entropy and expire).
* Assertions in subject information are passed through from the approval, not generated.
