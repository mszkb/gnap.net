# Interoperability (Phase 5)

gnap.net is tested against independent GNAP implementations:

| Peer | Language | Role | What runs |
|------|----------|------|-----------|
| [Rafiki](https://github.com/interledger/rafiki) auth service | TypeScript | AS (Open Payments) | `Gnap.Client` → Rafiki |
| [aaronpk/gnap-client-php](https://github.com/aaronpk/gnap-client-php) | PHP | Client | gnap-client-php → `Gnap.AspNetCore` AS |
| [http-message-signatures](https://www.npmjs.com/package/http-message-signatures) | JavaScript | RFC 9421 library | signatures in both directions |
| [@interledger/http-signature-utils](https://www.npmjs.com/package/@interledger/http-signature-utils) | JavaScript | Rafiki's signer/verifier | signatures in both directions |

All of it lives in `tests/Gnap.Interop.Tests` (xUnit) plus `interop/` (compose file,
run scripts, drivers). Every interop test is **skipped unless its peer is configured**
through environment variables, so `dotnet test Gnap.sln` stays hermetic. The
[Interop workflow](../.github/workflows/interop.yml) runs all three suites nightly and on
demand (`workflow_dispatch`, optionally with another `rafiki_auth_image`).

## Running locally

```bash
interop/run-signatures.sh     # needs node (npm ci in interop/signatures)
interop/run-php-client.sh     # needs php (curl, mbstring, openssl) + composer + git
interop/run-rafiki.sh         # needs docker compose (pulls ghcr.io/interledger/rafiki-auth)
```

`CONFIGURATION=Debug` selects the build configuration (default `Release`).

**Rafiki from source** (e.g. when ghcr.io is unreachable): start Postgres and Redis,
build `packages/auth` of a Rafiki checkout (`pnpm install --filter auth...`,
`pnpm --filter token-introspection build`, `tsc --build` in `packages/auth`, copy
`src/graphql/schema.graphql` and `src/openapi` into `dist/`), run
`node --env-file=<env> dist/index.js` with the environment of
`interop/rafiki/docker-compose.yml` (database/redis hosts adjusted to `localhost`),
then `RAFIKI_EXTERNAL=1 interop/run-rafiki.sh`.

| Variable | Default | Meaning |
|----------|---------|---------|
| `GNAP_INTEROP_RAFIKI` | — | enables the Rafiki tests |
| `RAFIKI_AUTH_URL` / `RAFIKI_INTERACTION_URL` / `RAFIKI_INTROSPECTION_URL` | `http://localhost:3006` / `:3009` / `:3007` | Rafiki auth ports |
| `RAFIKI_TENANT_ID`, `RAFIKI_IDP_SECRET` | compose values | operator tenant (grant endpoint `/{tenant}`), IdP secret |
| `INTEROP_WALLET_PORT`, `INTEROP_WALLET_BASE` | `5199`, `http://localhost:5199/` | the test's wallet address server and how Rafiki reaches it |
| `GNAP_INTEROP_PHP_CLIENT` | — | path of a prepared gnap-client-php checkout |
| `GNAP_INTEROP_PHP`, `INTEROP_AS_PORT` | `php`, `5299` | PHP binary, port of the .NET AS |
| `GNAP_INTEROP_NODE_SIGNATURES` | — | enables the signature cross-checks |

## Interop matrix

Status as of 2026-10-03: green locally against Rafiki `main` @ `3b2653b` (built from
source) and in CI against `ghcr.io/interledger/rafiki-auth:v2.4.1-beta` (both with
`@interledger/http-signature-utils` 2.0.2; `:latest` is an older single-tenant release
and answers 404 on the per-tenant grant endpoint); gnap-client-php @ `177edf0`.

| Flow / check | Test | Result |
|--------------|------|--------|
| .NET client → Rafiki: discovery | `RafikiInteropTests.Discovery_endpoint_is_reachable` | ✅ |
| .NET client → Rafiki: grant without interaction (`incoming-payment`), token introspection, rotation, revocation | `…Non_interactive_grant_issues_a_token_that_Rafiki_introspects_rotates_and_revokes` | ✅ after fixes 1+2 |
| .NET client → Rafiki: `redirect` interaction via Rafiki's IdP API, finish hash, continuation with `interact_ref`, token use (introspection), revocation (`outgoing-payment`) | `…Interactive_grant_completes_through_redirect_finish_and_continuation` | ✅ after fixes 1+3 |
| Rafiki rejects a signature by a key the client's JWKS does not publish | `…Rafiki_rejects_a_request_signed_with_a_key_the_wallet_does_not_publish` | ✅ |
| PHP client → .NET AS: redirect flow (key by value, RSA-PSS-SHA512, `sha3-512` finish hash, continuation covering `Authorization`) | `PhpClientInteropTests.Redirect_flow_with_sha3_512_finish_hash` | ✅ with the documented client patch |
| PHP client → .NET AS: same with default `sha-256` hash | `…Redirect_flow_with_default_sha_256_finish_hash` | ✅ with patch |
| PHP client unpatched → .NET AS | `GNAP_PHP_UNPATCHED=1 interop/run-php-client.sh` | ❌ `invalid_client` (expected, see below) |
| Our GNAP signatures → JS verifiers: Ed25519 + ECDSA P-256 × `sha-256`/`sha-512` `Content-Digest`, with/without `Authorization`, percent-encoded/reserved/empty query values, non-ASCII body | `NodeSignatureInteropTests.Our_GNAP_signatures_verify_in_the_JavaScript_implementations` | ✅ both libraries |
| JS signatures → our RFC 9421 verifier and GNAP proof validator: Ed25519 + ECDSA P-256 × `sha-256`/`sha-512`, mixed-case header names | `…JavaScript_signatures_verify_with_our_verifier_and_GNAP_proof_validator` | ✅ (Rafiki-style signatures: RFC 9421 ✅, GNAP proof ❌ by design, missing `tag`) |
| Our RS ← Rafiki-issued tokens | — | not applicable: Rafiki tokens are opaque and introspected via Rafiki's own (non-RFC 9767) introspection API |

## Findings

### Fixed in gnap.net

1. **HTML-safe JSON escaping broke `Content-Digest` at Rafiki.** `System.Text.Json`
   escapes `+ & < > '` and non-ASCII by default. Rafiki (koa-bodyparser) verifies
   `Content-Digest` against `JSON.stringify` of the *parsed* body, so a finish URI
   like `…?a=b+c` made every grant request fail with `invalid signature headers`.
   Outgoing messages now use `GnapJsonContext.Wire` (relaxed escaping; JSON syntax is
   still escaped). Regression: `InteropRegressionTests.WireSerialization_*`.
2. **`manage` as a bare URI.** Rafiki / Open Payments sends the pre-RFC draft form
   `"manage": "https://…/token/{id}"` and authorizes management requests with the
   access token itself. The client failed to parse grant responses. `TokenManagement`
   now reads both forms (`IsUriOnly`, `GetManagementTokenValue`) and the client rotates
   and revokes with the token value in that case. Regression:
   `InteropRegressionTests.UriOnlyManage_*`,
   `TokenManagementTests.UriOnlyManage_OpenPaymentsForm_RotatesAndRevokesWithTheAccessTokenItself`.
3. **Finish hash encoding.** Rafiki sends the interaction hash as padded standard
   base64 instead of base64url (RFC 9635 Section 4.2.3). `InteractionFinishHash.Verify`
   now also accepts exactly the canonical padded base64 spelling of the same hash bytes
   (any other spelling is still rejected). Regression:
   `InteropRegressionTests.FinishHash_*`.

### Deviations of the peers (not changed in gnap.net)

**Rafiki (Open Payments profile of GNAP):**

- Signatures carry no `tag="gnap"` (RFC 9635 Section 7.3.1 MUST) — our AS/RS reject
  Rafiki-style clients (Open Payments SDK). Kept strict; an opt-out could be added if
  serving Open Payments clients becomes a goal.
- `manage` is a URI string, finish `hash` is standard base64 (see fixes 2 and 3).
- Clients are identified by a wallet address string (or `{"jwk": …}`); RFC 9635
  `client.key` objects are not accepted. Our client works via `InstanceId = <wallet address>`.
- The verifier only understands the label `sig1`, requires `content-length` and
  `content-type` headers whenever `content-digest` is covered, and recomputes the digest
  over a re-serialized body (finding 1).
- Grant endpoint per tenant (`/{tenantId}`), interaction completion through a private
  IdP API (`/grant/{id}/{nonce}/accept` + `x-idp-secret`).

**gnap-client-php** (a 2022 sample written against draft-09, unmaintained):

- Signs `sha512(signature base)` with phpseclib, which hashes again → the signature is
  over the double hash and verifies with no RFC 9421 implementation.
- Sends `alg` (forbidden by RFC 9635 Section 7.3.1) and no `tag="gnap"`.
- Sends no `nonce` (RFC: SHOULD) — the interop AS sets `RequireSignatureNonce = false`.
- Requests `hash_method: "sha3"` (draft name; RFC 9635 uses `sha3-512`) — the driver
  requests registered names.

`interop/php-client/rfc9635-signatures.patch` fixes the first two (two lines); the
remaining code (key by value as JWK, `content-digest`, `@target-uri`, `authorization`
coverage, finish hash formula, continuation) is used unchanged.

**Upstream reports:** not filed yet (needs the maintainer's decision). Candidates:
Rafiki — `tag="gnap"`, `manage` object form, base64url finish hash, digest over raw
body; gnap-client-php — double hashing, `alg`/`tag`.

## RFC 9635 conformance checklist (MUST requirements)

✅ implemented and tested · ➖ not applicable / optional feature not implemented

| § | Requirement (MUST) | Client | AS | RS | Tests |
|---|--------------------|:------:|:--:|:--:|-------|
| 2 | Grant request is a JSON object POSTed to the grant endpoint, signed with the client's key proof | ✅ | ✅ | | `GrantFlowTests.*`, `SecurityTests.UnsignedOrMissignedGrantRequest_IsRejected`, PHP + Rafiki interop |
| 2.1 | `access_token` single object or array; multiple tokens MUST carry unique `label`s | ✅ | ✅ | | `JsonModelTests.SingleAccessTokenRequest_SerializesAsObject`, `EndToEndTests.MultipleLabeledTokens_AndBearer` |
| 2.3 | Client key MUST be presented by value or reference; AS MUST verify the proof with that key | ✅ | ✅ | | `ErrorHandlingTests.InvalidClient_WhenSignatureDoesNotMatchPresentedKey`, `SecurityTests.UnknownInstanceAndKeyReferences_AreRejected`, `RafikiInteropTests.Rafiki_rejects_…` |
| 2.3 | Request MUST NOT contain private key material | | ✅ | | `SecurityTests.MalformedJsonAndPrivateKeyMaterial_AreRejected` |
| 2.5.2 | Finish `nonce` MUST be unique per request; unsupported `hash_method` rejected | ✅ | ✅ | | `FinishHashTests.UnsupportedHashMethod_IsRejectedBeforeSending`, `EndToEndTests.RedirectFlow_HonoursHashMethod` |
| 3.1 | Continuation access token MUST be bound to the client key and MUST NOT be usable at the RS | ✅ | ✅ | | `SecurityTests.ContinuationSignedWithOtherKey_IsRejected` |
| 3.2 | Issued tokens bound to the client key unless `bearer`; bearer only if allowed | ✅ | ✅ | ✅ | `EndToEndTests.MultipleLabeledTokens_AndBearer`, `ResourceServerTests.BearerTokens_OnlyWhenAllowed` |
| 3.6 | Errors use the registered codes; descriptions MUST NOT leak internals | ✅ | ✅ | | `ErrorHandlingTests.EveryRegisteredErrorCode_SurfacesTyped`, `SecurityTests.ErrorDescriptionsAreGeneric` |
| 4.1 | Interaction bound to the user's session; user code single use | | ✅ | | `SecurityTests.InteractionIsBoundToTheFirstBrowser`, `SecurityTests.UserCodeIsSingleUse` |
| 4.2 | Finish: AS MUST send `hash` + `interact_ref`; client MUST verify the hash before continuing | ✅ | ✅ | | `FinishHashTests.*`, `InteractionFinishHashTests.*` (RFC vectors), PHP + Rafiki interop |
| 4.2.3 | Hash over client nonce, AS nonce, `interact_ref`, grant endpoint URI, base64url | ✅ | ✅ | | `InteractionFinishHashTests.Sha256_MatchesSpecVector`, PHP interop (`sha-256`, `sha3-512`) |
| 5 | Continuation MUST be signed by the same key and present the continuation token; `interact_ref` single use; `wait` honoured (`too_fast`) | ✅ | ✅ | | `SecurityTests.TamperedInteractRef_IsRejectedAndGrantUntouched`, `…SecondContinuationWithUsedInteractRef_IsUnknownInteraction`, `…PollingBeforeWait_IsTooFast`, `ErrorHandlingTests.TooFast_*` |
| 5.2 | Continuation token rotated on each poll response | ✅ | ✅ | | `GrantFlowTests.UserCodeFlow_PollsRespectingWaitAndAdoptsRotatedContinuationTokens`, `EndToEndTests.UserCodeFlow_PendingPollsRotateContinuationToken` |
| 5.4 | Grant revocation revokes its tokens | ✅ | ✅ | | `EndToEndTests.GrantRevocation_RevokesItsTokens` |
| 6 | Token management requires the management token and the client key proof; old value invalid after rotation | ✅ | ✅ | | `SecurityTests.TokenManagementRequiresManagementTokenAndKey`, `TokenManagementTests.*`, Rafiki interop |
| 6.1.2 | Key rotation MUST prove possession of old and new key | ✅ | ✅ | | `TokenManagementTests.KeyRotation_ProvesBothKeysAndRebindsToken`, `SecurityTests.KeyRotationWithoutProofOfNewKey_IsRejected` |
| 7.2 | Key-bound tokens MUST be presented with a proof by the bound key | ✅ | | ✅ | `ResourceServerTests.KeyBoundToken_WithoutValidSignature_IsRejected`, `TokenBoundToForeignKey_CannotBePresented` |
| 7.3.1 | httpsig: cover `@method`, `@target-uri`, `content-digest` (with content), `authorization` (with token); `tag="gnap"`; `created`; no `alg`; `keyid` = JWK `kid` | ✅ | ✅ | ✅ | `HttpSigProofingTests.*` (`MissingGnapTag_IsRejected`, `AdvertisedAlgParameter_IsRejected`, `StrippedContentDigest_IsRejected`, `AuthorizationAddedAfterSigning_IsRejected`, `KeyIdMismatch_…`), signature cross-checks |
| 7.3.1 | Verifier MUST examine all signatures until one is acceptable | | ✅ | ✅ | `HttpSigKeyProofValidator` label loop; `NegativeVerificationTests` |
| 7.3.2–7.3.4 | `mtls`, `jwsd`, `jws` proofing | ➖ | ➖ | ➖ | not implemented (optional; `httpsig` only) — requests using them are rejected with `invalid_client` |
| 8 | Resource access rights: AS MUST NOT grant more than requested/approved | | ✅ | ✅ | `EndToEndTests.ConsentNarrowsAccessAndReleasesSubject`, `PolicyAndStateMachineTests.PolicyCanNarrowAccessPerToken`, `ResourceServerTests.Requirement_MatchesReferencesAndTypedRights` |
| 9 | Discovery document at the grant endpoint (OPTIONS) / `.well-known` | ✅ | ✅ | | `DiscoveryTests.*`, `EndToEndTests.Discovery_ClientReadsAsMetadata` |
| 11 | Replay protection: `created` window, nonces | ✅ | ✅ | ✅ | `SecurityTests.ReplayedGrantRequest_IsRejected`, `…SignatureOutsideCreatedWindow_IsRejected`, `ResourceServerTests.ReplayedRequest_IsRejected` |

Documented deviations from MUST requirements: none in gnap.net. The only leniencies
are on the *receiving* side for peers on earlier drafts (URI-only `manage`, padded
base64 finish hash) and do not weaken the checks: the same hash bytes are compared,
and URI-only management still requires a valid key proof by the token's key.
