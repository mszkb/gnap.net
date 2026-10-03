# Architecture

This page shows how the gnap.net packages fit together and how the GNAP flows run
through them. The diagrams are [Mermaid](https://mermaid.js.org/) and render directly
on GitHub. For the protocol background read [GNAP for Dummies](gnap-for-dummies.md);
for the security analysis, the [threat model](threat-model.md).

## Contents

1. [Packages and dependencies](#1-packages-and-dependencies)
2. [Components at runtime](#2-components-at-runtime)
3. [Inside the authorization server](#3-inside-the-authorization-server)
4. [Flow: redirect interaction with finish callback](#4-flow-redirect-interaction-with-finish-callback)
5. [Flow: user code](#5-flow-user-code)
6. [Flow: push finish](#6-flow-push-finish)
7. [Flow: policy approval without interaction](#7-flow-policy-approval-without-interaction)
8. [Flow: calling the resource server (introspection)](#8-flow-calling-the-resource-server-introspection)
9. [Flow: RS-first discovery](#9-flow-rs-first-discovery)
10. [Flow: token rotation, key rotation, revocation](#10-flow-token-rotation-key-rotation-revocation)
11. [Grant state machine](#11-grant-state-machine)
12. [The httpsig key proof on every request](#12-the-httpsig-key-proof-on-every-request)

## 1. Packages and dependencies

```mermaid
flowchart BT
    HMS["<b>Gnap.HttpMessageSignatures</b><br/>RFC 9421 / 9530 / 8941<br/>signer, verifier, Content-Digest,<br/>DelegatingHandler, nonce store"]
    HMSA["<b>Gnap.HttpMessageSignatures.AspNetCore</b><br/>verification middleware"]
    CORE["<b>Gnap.Core</b><br/>JWK + thumbprints, httpsig key proofing,<br/>finish hash, JSON models (AOT)"]
    CLIENT["<b>Gnap.Client</b><br/>discovery, grants, interaction,<br/>continuation, token management"]
    ASP["<b>Gnap.AspNetCore</b><br/>authorization server + resource server"]
    BC[(BouncyCastle<br/>Ed25519 only)]
    FX[(Microsoft.AspNetCore.App)]

    HMS --> BC
    HMSA --> HMS
    HMSA --> FX
    CORE --> HMS
    CLIENT --> CORE
    ASP --> CORE
    ASP --> HMSA
    ASP --> FX
```

`Gnap.HttpMessageSignatures` has no GNAP knowledge and can be used on its own.
`Gnap.Core` and `Gnap.Client` are trimming- and Native-AOT-compatible and have no
ASP.NET Core dependency.

## 2. Components at runtime

```mermaid
flowchart LR
    subgraph Client["Client instance (Gnap.Client)"]
        GC[GnapClient]
        TS[GnapTokenSource]
        TH[GnapAccessTokenHandler]
    end
    subgraph AS["Authorization server (Gnap.AspNetCore)"]
        GE["/gnap/tx<br/>grant endpoint"]
        CE["/gnap/continue/{id}"]
        IE["/gnap/interact/{id}<br/>/gnap/device"]
        TM["/gnap/token/{id}"]
        INT["/gnap/introspect<br/>/gnap/resource"]
        UI[Consent UI<br/>IGnapInteractionService]
    end
    subgraph RS["Resource server (Gnap.AspNetCore)"]
        MW[UseGnapResourceServer<br/>GNAP auth handler]
        API[Endpoints<br/>RequireGnapAccess]
    end
    User((Resource owner<br/>browser))

    GC -- signed grant request --> GE
    GC -- signed continuation --> CE
    TS -- rotate / revoke --> TM
    User -- interaction --> IE --> UI
    TH -- "Authorization: GNAP + signature" --> MW --> API
    MW -- signed introspection --> INT
```

Every arrow from the client and the RS to the AS is an HTTP request signed with
RFC 9421 (`httpsig` key proofing); the AS verifies each one against the key the
grant or the resource server registration is bound to.

## 3. Inside the authorization server

```mermaid
flowchart TB
    REQ[HTTP request] --> KPV[KeyProofVerifier<br/>signature, digest, created, nonce]
    KPV --> EP{Endpoint}
    EP -->|/tx| GEP[GrantEndpoint]
    EP -->|/continue| CEP[ContinuationEndpoint]
    EP -->|/token| TMP[Token management]
    EP -->|/introspect| IEP[IntrospectionEndpoint]
    GEP --> POL[IGrantPolicy<br/>deny by default]
    POL -->|Approve| ISS[GrantIssuer]
    POL -->|RequireInteraction| INTR[Interaction<br/>redirect / user code]
    CEP --> ISS
    ISS --> FMT[ITokenFormat<br/>opaque or JWT]
    GEP & CEP & TMP & ISS --> GS[(IGrantStore)]
    ISS & TMP & IEP --> TKS[(ITokenStore)]
    GEP --> CKS[(IClientKeyStore)]
    IEP --> RSS[(IResourceServerStore)]
```

All stores, the policy, the token format and the interaction page are interfaces
registered in DI with in-memory defaults; the example AS replaces the stores with
EF Core.

## 4. Flow: redirect interaction with finish callback

The flow of a web application (RFC 9635 §2, §4.1.1, §4.2.1, §5.1).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (Gnap.Client)
    participant B as Browser (resource owner)
    participant AS as Authorization server
    C->>AS: POST /gnap/tx (signed)<br/>access, client.key, interact {start: redirect, finish: {method: redirect, uri, nonce}}
    AS->>AS: verify key proof, IGrantPolicy → RequireInteraction
    AS-->>C: interact.redirect, interact.finish (AS nonce), continue {uri, access_token, wait}
    C->>B: redirect to interact.redirect
    B->>AS: GET /gnap/interact/{id}
    AS->>B: bind interaction to this browser (cookie), show consent
    B->>AS: approve
    AS-->>B: 302 to client callback ?hash=…&interact_ref=…
    B->>C: GET callback ?hash&interact_ref
    C->>C: verify finish hash (client nonce, AS nonce, interact_ref, grant endpoint)
    C->>AS: POST continue.uri (signed, GNAP continuation token) {interact_ref}
    AS-->>C: access_token {value, manage, expires_in, key-bound}, new continue token
```

## 5. Flow: user code

For devices without a browser (RFC 9635 §4.1.2, §4.1.3). The client polls.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (console app)
    participant U as Resource owner (any browser)
    participant AS as Authorization server
    C->>AS: POST /gnap/tx (signed) interact {start: [user_code_uri]}
    AS-->>C: user_code_uri {code: ABCD-EFGH, uri: /gnap/device}, continue {wait: 5}
    C->>U: display code and URI
    loop until approved or denied (honours wait, too_fast back-off)
        C->>AS: POST continue.uri (signed)
        AS-->>C: continue (pending) with rotated continuation token
    end
    U->>AS: GET /gnap/device, enter ABCD-EFGH (single use)
    AS->>U: consent
    U->>AS: approve
    C->>AS: POST continue.uri (signed)
    AS-->>C: access_token
```

## 6. Flow: push finish

The AS notifies the client server-to-server instead of through the browser
(RFC 9635 §4.2.2).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant B as Browser
    participant AS as Authorization server
    C->>AS: POST /gnap/tx interact {start: [redirect], finish: {method: push, uri, nonce}}
    AS-->>C: interact.redirect, finish nonce, continue
    B->>AS: interaction + consent
    AS->>C: POST finish uri {hash, interact_ref}
    C->>C: verify finish hash
    C->>AS: POST continue.uri {interact_ref}
    AS-->>C: access_token
```

## 7. Flow: policy approval without interaction

A registered client instance (e.g. a service) can be approved by the policy directly;
then the first response already carries the token. (Polling for a pending decision is
shown in flow 5.)

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as Authorization server
    C->>AS: POST /gnap/tx (signed) client: "instance-id"
    AS->>AS: IClientKeyStore resolves the key, IGrantPolicy → Approve
    AS-->>C: access_token (+ continue for later revocation)
```

## 8. Flow: calling the resource server (introspection)

RFC 9635 §7.2, §7.3.1 and RFC 9767 §3.3.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RS as Resource server
    participant AS as Authorization server
    C->>RS: GET /photos<br/>Authorization: GNAP <token><br/>Signature-Input: …tag="gnap" (@method @target-uri authorization [content-digest])
    RS->>RS: cache lookup (IntrospectionCacheDuration)
    alt cache miss
        RS->>AS: POST /gnap/introspect (signed by the RS key) {access_token, resource_server, proof: httpsig, access}
        AS-->>RS: {active: true, access, key, exp, …} or {active: false}
    end
    RS->>RS: verify the request signature with the token's bound key, nonce unseen
    RS->>RS: RequireGnapAccess("photo-api", "read")
    RS-->>C: 200, or 401 / 403 with WWW-Authenticate: GNAP as_uri=…, access=…
```

With JWT tokens (`UseJwtTokens`) or a co-hosted AS (`UseLocalTokenStore`) the
introspection round-trip is replaced by local validation; the key-proof check stays.

## 9. Flow: RS-first discovery

The client starts at the resource and learns where to get a token (RFC 9635 §9.2,
RFC 9767 §3.4).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant RS as Resource server
    participant AS as Authorization server
    RS->>AS: POST /gnap/resource (signed) {access: [...]} (once)
    AS-->>RS: {resource_reference: "r-123"}
    C->>RS: GET /photos (no token)
    RS-->>C: 401 WWW-Authenticate: GNAP as_uri="https://as/gnap/tx", access="r-123"
    C->>AS: POST /gnap/tx access: ["r-123"]
    Note over C,AS: continues as in flows 4–7
```

## 10. Flow: token rotation, key rotation, revocation

RFC 9635 §6.1, §6.1.2, §6.2 and §5.4. `GnapTokenSource` rotates automatically on
expiry.

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as Authorization server
    C->>AS: POST manage.uri (signed, current key)
    AS-->>C: new token value (old value revoked, single use)
    C->>AS: POST manage.uri {key: new key}<br/>signed by the current AND the new key
    AS-->>C: token now bound to the new key
    C->>AS: DELETE manage.uri
    AS-->>C: 204 (token revoked)
    C->>AS: DELETE continue.uri
    AS-->>C: 204 (grant and all its tokens revoked)
```

## 11. Grant state machine

`GrantRecord.TransitionTo` enforces the RFC 9635 §1.5 states; illegal transitions
throw.

```mermaid
stateDiagram-v2
    [*] --> Processing: grant request
    Processing --> Pending: interaction required
    Processing --> Approved: policy approval
    Pending --> Approved: resource owner approves
    Approved --> Finalized: tokens issued
    Processing --> Revoked
    Pending --> Revoked: denied / expired
    Approved --> Revoked
    Finalized --> Revoked: DELETE continue
    Revoked --> [*]
    Finalized --> [*]
```

## 12. The httpsig key proof on every request

```mermaid
flowchart LR
    subgraph Signer["Client: HttpMessageSigner"]
        A[request] --> D[Content-Digest<br/>sha-256 / sha-512]
        D --> SB1[signature base<br/>@method, @target-uri,<br/>authorization, content-digest,<br/>created, nonce, keyid, tag]
        SB1 --> S[sign with private key]
        S --> H[Signature-Input + Signature]
    end
    subgraph Verifier["AS / RS: key proof verification"]
        H --> P[parse fields]
        P --> K{keyid → bound key<br/>alg pinned}
        K --> SB2[rebuild signature base]
        SB2 --> V[verify signature]
        V --> T[created within MaxAge ± ClockSkew]
        T --> N[nonce never seen → record]
        N --> DG[digest matches body]
        DG --> OK[accept]
    end
```

A failure at any step produces the same generic error response; the precise reason is
logged on the server only (no oracle).
