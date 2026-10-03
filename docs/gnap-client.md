# Using Gnap.Client

`Gnap.Client` is the client side of GNAP ([RFC 9635](https://datatracker.ietf.org/doc/rfc9635/))
on top of `Gnap.Core` (Phase 1) and `Gnap.HttpMessageSignatures` (Phase 0). It runs
anywhere `HttpClient` runs — console apps, workers, desktop apps, ASP.NET Core —
and has no ASP.NET Core dependency. If the vocabulary below is new, read
[GNAP for Dummies](gnap-for-dummies.md) first.

## Contents

1. [The 30-second version](#1-the-30-second-version)
2. [Keys](#2-keys)
3. [Interaction: redirect, push, user code](#3-interaction-redirect-push-user-code)
4. [Web apps: the step-wise API](#4-web-apps-the-step-wise-api)
5. [Continuation, polling and `wait`](#5-continuation-polling-and-wait)
6. [Using and managing tokens](#6-using-and-managing-tokens)
7. [Discovery](#7-discovery)
8. [Errors](#8-errors)
9. [Dependency injection](#9-dependency-injection)
10. [Map of the API](#10-map-of-the-api)
11. [What is not covered (yet)](#11-what-is-not-covered-yet)

## 1. The 30-second version

```csharp
using Gnap.Client;
using Gnap.Client.Interaction;
using Gnap.Core.Models;

var client = new GnapClient(new HttpClient(), new GnapClientOptions
{
    GrantEndpoint = new Uri("https://as.example/tx"),
    ClientKey = GnapClientKey.FromJwk(myPrivateJwk),     // signs every request (httpsig)
    Display = new ClientDisplay { Name = "Photo Printer" },
});

var result = await client.RequestAccessAsync(
    [new AccessRight { Type = "photo-api", Actions = ["read"] }],
    GnapInteractionHandler.UserCode((interaction, _) =>
    {
        Console.WriteLine($"Go to {interaction.UserCodeUri?.Uri} and enter {interaction.UserCodeUri?.Code ?? interaction.UserCode}");
        return ValueTask.CompletedTask;
    }));

Console.WriteLine(result.AccessToken!.Value);
```

`RequestAccessAsync` sends the signed grant request, shows the interaction via the
handler, verifies the finish callback (if any), continues or polls the grant while
respecting `wait`, and returns the tokens.

## 2. Keys

`GnapClientKey` couples the private signing key with what the AS is shown:

| Factory | Sent to the AS |
|---|---|
| `GnapClientKey.FromJwk(jwk)` | `"key": { "proof": "httpsig", "jwk": { …public part… } }` |
| `GnapClientKey.FromJwk(jwk, ContentDigestAlgorithm.Sha512)` | object-form proof pinning `alg` and `content-digest-alg` |
| `key.WithReference("key-ref")` | `"key": "key-ref"` (Section 7.1.1) — still signs with the private key |

Set `GnapClientOptions.InstanceId` to send `"client": "<instance id>"` instead of
the key object (Section 2.3.1). Requests are signed either way.

## 3. Interaction: redirect, push, user code

An `IGnapInteractionHandler` declares the `interact` request and runs the
interaction. Three ready-made handlers:

```csharp
// Redirect start + redirect finish: open the browser, await the callback URI.
GnapInteractionHandler.Redirect(new Uri("http://127.0.0.1:7777/callback"), async (interaction, ct) =>
{
    SystemBrowser.Open(interaction.RedirectUri!);
    return await myLocalListener.WaitForCallbackAsync(ct);   // the full URI incl. ?hash=…&interact_ref=…
});

// User code (device style), no callback: show the code, the client polls.
GnapInteractionHandler.UserCode((interaction, ct) => ShowCodeAsync(interaction, ct));

// Anything else (push finish, app start, hints, …).
GnapInteractionHandler.Create(myInteractRequest, async (interaction, ct) =>
    GnapInteractionOutcome.FromPush(await myPushEndpoint.WaitForBodyAsync(ct)));
```

The client generates the finish `nonce` itself, and before continuing it verifies
the finish `hash` (Section 4.2.3) against its nonce, the AS nonce and the grant
endpoint in constant time. A missing, repeated or wrong `hash`/`interact_ref`, a
callback the client never asked for, or a second callback for the same grant
throws `GnapInteractionException` and the grant is **not** continued.

> The grant endpoint enters the hash exactly as `GrantEndpoint.AbsoluteUri`;
> configure it the way the AS publishes it.

## 4. Web apps: the step-wise API

In a web app the redirect back arrives in a different HTTP request. Split the flow:

```csharp
// Request 1: start, keep the pending grant (e.g. in the session/cache), redirect the user.
var pending = await client.StartGrantAsync(new GrantRequest
{
    AccessToken = [new AccessTokenRequest { Access = [AccessRight.ForReference("photo-api")] }],
    Interact = new InteractRequest
    {
        Start = [new StartMode(StartModes.Redirect)],
        Finish = new InteractFinish { Method = FinishMethods.Redirect, Uri = "https://app.example/gnap/callback" },
    },
});
return Redirect(pending.Interaction!.RedirectUri!.AbsoluteUri);

// Request 2 (the callback): verify and finish.
var result = await pending.CompleteWithRedirectAsync(new Uri(Request.GetEncodedUrl()));
```

`CompleteWithPushAsync(body)` does the same for the `push` finish method.
`pending.CancelAsync()` revokes the grant (Section 5.4); `client.Protocol.UpdateGrantAsync`
modifies it (Section 5.3).

## 5. Continuation, polling and `wait`

* Every continuation call is signed and carries the **latest** continuation access
  token — the AS may rotate it on every response and the client adopts it.
* The client never calls the continuation URI before `wait` seconds have passed
  (five when the AS omits `wait`).
* On `too_fast` it backs off exponentially (doubling, at least 1 s, at most
  `MaxPollingInterval`, default 60 s) and keeps polling.
* Polling gives up after `MaxPollingDuration` (default 15 min) with a `GnapClientException`.
* HTTP 5xx and transport failures are retried `MaxRetries` times (default 3) with
  exponential back-off from `RetryBaseDelay`, honouring `Retry-After`; each retry
  carries a **fresh** signature (new `created` and `nonce`), so the AS's replay
  protection does not reject it.

All timing goes through `GnapClientOptions.TimeProvider`, which makes it testable.

## 6. Using and managing tokens

```csharp
using Gnap.Client.Tokens;

var tokens = client.CreateTokenSource(result.AccessToken!);      // self-refreshing holder
var api = new HttpClient(new GnapAccessTokenHandler(tokens, new SocketsHttpHandler()));
var photos = await api.GetStringAsync("https://rs.example/photos");
```

`GnapAccessTokenHandler` sets `Authorization: GNAP <token>` and, for key-bound
tokens, signs the request with the bound key (covering the `Authorization`
header). Bearer tokens are sent without a signature.

GNAP has no refresh tokens; **rotation is the refresh**:

| Operation | API | RFC 9635 |
|---|---|---|
| Rotate value | `client.RotateTokenAsync(token)` | Section 6.1.1 (`POST` to `manage.uri`) |
| Rotate bound key | `client.RotateTokenKeyAsync(token, newKey)` / `tokenSource.RotateKeyAsync(newKey)` | Section 6.1.2 — signed by both keys, the new key's signature covers the old one (`"signature";key="sig1"`, `"signature-input";key="sig1"`) |
| Revoke | `client.RevokeTokenAsync(token)` / `tokenSource.RevokeAsync()` | Section 6.2 (`DELETE`) |
| Automatic refresh | `GnapTokenSource.GetTokenAsync()` rotates when `expires_in` is within `TokenRefreshSkew` (30 s); the handler also rotates once and retries when the RS answers 401 | — |
| Client key rotation | `client.UseClientKey(newKey)` — future grants use the new key | — |

Concurrent callers share one rotation (the token source serialises it). Tokens
without `manage` cannot be rotated; when they expire `GetTokenAsync` throws and
you request a new grant.

## 7. Discovery

```csharp
var metadata = await client.DiscoverAsync();     // OPTIONS on the grant endpoint (Section 9), cached
if (!metadata.SupportsFinishMethod(FinishMethods.Push)) { /* fall back */ }

var wellKnown = await client.Discovery.GetWellKnownMetadataAsync(new Uri("https://as.example"));  // /.well-known/gnap-as-rs (RFC 9767)

// RS-first discovery (Section 9.1): the RS's 401 names the AS and an access reference.
if (GnapResourceChallenge.TryParse(response, out var challenge))
{
    // challenge.AsUri = grant endpoint, challenge.Access = access reference to request
}
```

Metadata is cached per URI for `MetadataCacheDuration` (1 h) or the response's
`Cache-Control: max-age`; `no-store`/`no-cache` disable caching. Register one
`GnapMetadataCache` to share it between client instances (DI does this).

## 8. Errors

| Exception | When |
|---|---|
| `GnapProtocolException` | The AS returned a GNAP `error` (string or object form). `ex.Code` is a typed `GnapErrorCode` (all 13 registered codes, plus extensions), `ex.Error.Description`, `ex.StatusCode`, `ex.Response`. |
| `GnapInteractionException` | The finish callback failed verification (Section 4.2.3). |
| `GnapClientException` | Base class; also: AS unreachable after retries, unexpected status without GNAP body, malformed JSON, polling timeout, token not manageable. |

```csharp
catch (GnapProtocolException e) when (e.Code == GnapErrorCode.UserDenied) { … }
```

Nothing fails silently: a non-success status always throws, with the GNAP error
when the body carries one.

## 9. Dependency injection

```csharp
services.AddGnapClient(o =>
{
    o.GrantEndpoint = new Uri("https://as.example/tx");
    o.ClientKey = GnapClientKey.FromJwk(jwk);
});   // returns the IHttpClientBuilder for handlers / the primary handler
```

Do not add a generic retry handler to this pipeline: it would re-send the same
signed request, which an AS with replay protection rejects. `GnapClient` retries
itself, re-signing every attempt.

Registers a transient `GnapClient` on the named `IHttpClientFactory` client
`GnapClient.HttpClientName` and a singleton `GnapMetadataCache`.

## 10. Map of the API

| Type | Role |
|---|---|
| `GnapClient` | High level: `RequestAccessAsync`, `StartGrantAsync`, `DiscoverAsync`, token rotation/revocation, `CreateTokenSource`, `UseClientKey` |
| `GnapPendingGrant` | A grant in flight: `CompleteWithRedirectAsync`, `CompleteWithPushAsync`, `PollAsync`, `ContinueOnceAsync`, `CancelAsync` |
| `GnapProtocolClient` (`client.Protocol`) | Low level: one signed call per protocol step (grant, continue, update, cancel, rotate, rotate key, revoke) with retries and error mapping |
| `GnapClientKey` | Private key + presented key (by value or reference) + proofer factory |
| `IGnapInteractionHandler`, `GnapInteractionHandler`, `GnapInteraction`, `GnapInteractionOutcome`, `SystemBrowser` | Interaction |
| `GnapAccessToken`, `GnapTokenSource`, `GnapAccessTokenHandler` | Token use and management |
| `GnapDiscoveryClient`, `GnapMetadataCache`, `AuthorizationServerMetadata`, `GnapResourceChallenge` | Discovery |

## 11. What is not covered (yet)

* Only the `httpsig` proofing method (as in Phase 1); `mtls`, `jwsd`, `jws` need their own `IKeyProofer`.
* Tokens bound to a key other than the client's (`key` in the token response) cannot be presented automatically.
* No built-in loopback HTTP listener for redirect callbacks in console apps — use any listener and hand the URI to the handler.
* Tested against an in-memory mock AS; interoperability with external AS implementations is Phase 5.
