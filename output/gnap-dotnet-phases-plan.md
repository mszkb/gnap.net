# GNAP für .NET — Implementierungsplan

Ein inkrementeller 7-Phasen-Plan für eine vollständige, RFC-konforme GNAP-Implementierung
(Grant Negotiation and Authorization Protocol, **RFC 9635** / **RFC 9767**) in .NET,
inklusive HTTP Message Signatures (**RFC 9421**) als kryptografischer Basis.

**Zielplattform:** .NET 10 (LTS), ASP.NET Core
**Sprache:** C# (latest), Nullable Reference Types, Source-Generated JSON Serialization
**Lizenz:** siehe `LICENSE` im Repository-Root

---

## Inhaltsverzeichnis

- [Leitprinzipien](#leitprinzipien)
- [Dependency Graph](#dependency-graph)
- [Phase 0 — HTTP Message Signatures (RFC 9421)](#phase-0--http-message-signatures-rfc-9421)
- [Phase 1 — GNAP Core Primitives](#phase-1--gnap-core-primitives)
- [Phase 2 — Client Library](#phase-2--client-library)
- [Phase 3 — Authorization Server](#phase-3--authorization-server)
- [Phase 4 — Resource Server Middleware](#phase-4--resource-server-middleware)
- [Phase 5 — Interoperability Testing](#phase-5--interoperability-testing)
- [Phase 6 — Polish, Docs & Release](#phase-6--polish-docs--release)
- [Test-Strategie](#test-strategie)
- [Package-Übersicht](#package-übersicht)
- [Quellen](#quellen)

---

## Leitprinzipien

1. **Strikte Dependency-Kette.** Jede Phase baut ausschließlich auf abgeschlossenen
   vorherigen Phasen auf. Keine Phase beginnt, bevor die Akzeptanzkriterien der
   Vorgängerphase erfüllt sind.
2. **Krypto zuerst.** IETF-Hackathon-Erfahrungen (GNAPathon) zeigen: HTTP Message
   Signatures sind der schwierigste und fehleranfälligste Teil von GNAP. Deshalb
   werden sie isoliert, testvektor-getrieben und als eigenständiges Package gebaut.
3. **Test-Vektoren vor eigenem Code.** Wo RFCs Test-Vektoren liefern (RFC 9421
   Appendix B), werden diese zuerst als Tests implementiert — der Produktionscode
   wird dagegen entwickelt.
4. **Jede Phase liefert ein nutzbares Artefakt.** Kein „Big Bang": Phase 0 ergibt
   ein allgemein verwendbares RFC-9421-Package, Phase 2 einen funktionsfähigen
   Client gegen fremde AS, usw.
5. **Security by Default.** Konstante Fehlermeldungen (kein Oracle), Replay-Schutz,
   Zeitfenster-Validierung, keine Krypto-Eigenbauten — nur `System.Security.Cryptography`
   bzw. geprüfte Primitives.

---

## Dependency Graph

```
Phase 0: Gnap.HttpMessageSignatures (RFC 9421 + RFC 9530)
   │
   ▼
Phase 1: Gnap.Core (JWK, Key Proofing, Modelle)
   │
   ├──────────────┐
   ▼              ▼
Phase 2:       Phase 3:
Gnap.Client    Gnap.AspNetCore (AS)
   │              │
   └──────┬───────┘
          ▼
Phase 4: Gnap.AspNetCore (RS Middleware)
          │
          ▼
Phase 5: Interop (Rafiki, gnap-client-php)
          │
          ▼
Phase 6: Docs, NuGet Release, CI/CD
```

---

## Phase 0 — HTTP Message Signatures (RFC 9421)

**Ziel:** Eigenständiges, wiederverwendbares NuGet-Package `Gnap.HttpMessageSignatures`,
das RFC 9421 vollständig implementiert und unabhängig von GNAP nutzbar ist.

### Aufgaben

- [x] **Projekt-Setup:** Solution-Struktur, `Directory.Build.props`, Analyzer
      (`EnableNETAnalyzers`, Warnings-as-Errors); zentrale Package-Versionen und
      `.editorconfig` folgen bei Bedarf
- [x] **`SignatureBaseBuilder`:** Kanonische Signature Base gemäß RFC 9421 §2.5
  - [x] Component Identifier: HTTP-Felder (lowercase, strukturierte Felder via
        `sf`/`key`/`bs`/`tr`/`req`-Parameter)
  - [x] Derived Components: `@method`, `@target-uri`, `@authority`, `@scheme`,
        `@request-target`, `@path`, `@query`, `@query-param`, `@status`
  - [x] Parameter: `created`, `expires`, `nonce`, `alg`, `keyid`, `tag`
  - [x] `@signature-params`-Zeile (Structured Fields Serialization, RFC 8941 —
        eigener Parser/Serializer in `StructuredFields/`)
- [x] **Signer:** `HttpMessageSigner` über `SignatureAlgorithm`-Abstraktion
  - [x] Ed25519 (`ed25519`, via BouncyCastle — auch .NET 10 bietet keine eigenständige
        öffentliche Ed25519-API; Ed25519 taucht dort nur als Teil der
        Composite-ML-DSA-Algorithmen auf, z. B. `CompositeMLDsaAlgorithm.MLDsa65WithEd25519`)
  - [x] ECDSA P-256 / SHA-256 (`ecdsa-p256-sha256`)
  - [x] ECDSA P-384 / SHA-384 (`ecdsa-p384-sha384`)
  - [x] RSA-PSS / SHA-512 (`rsa-pss-sha512`) + RSA v1.5 / SHA-256 (`rsa-v1_5-sha256`)
  - [x] HMAC-SHA256 (`hmac-sha256`) — für Tests/Introspection
- [x] **Verifier:** `HttpMessageVerifier` — Parsing von `Signature`/`Signature-Input`
      Headern, Multi-Signature-Support, Zeitfenster (`created`/`expires`) mit
      konfigurierbarem Clock Skew, MaxAge, Required Components, alg/key-Mismatch-Schutz
- [x] **Content-Digest (RFC 9530):** `sha-256`/`sha-512` Digest-Erzeugung und
      -Verifikation, Integration in die Signature Base
- [x] **ASP.NET Core Middleware:** `UseHttpMessageSignatureVerification()` +
      `HttpSignatureDelegatingHandler` für `HttpClient` (automatisches Signieren
      inkl. Content-Digest ausgehender Requests)
- [x] **Key-Abstraktion:** `SignatureAlgorithm` / `IVerificationKeyResolver` +
      `PemKeyLoader` (inkl. RSASSA-PSS-OID-PKCS#8-Workaround; JWK folgt in Phase 1)
- [x] **Beispiel-Apps für manuelles Testen:** `examples/HttpSignatures.Demo`
      (Vektoren + Live-Demo in einem Prozess), `examples/VerifyingServer`
      (eigenständiger Kestrel-RS) und `examples/SigningClient` (CLI-Client, druckt
      Signature Base und Header)

### Tests

- [x] Alle Test-Vektoren aus RFC 9421 **Appendix B** (B.1 Beispiel-Keys, B.2.1–B.2.6
      Signaturen, B.3 TLS-terminierender Proxy, B.4 Header-Reordering/Transformationen)
- [x] Roundtrip: Sign → Verify für alle Algorithmen
- [x] Negative Tests: manipulierte Komponenten, abgelaufene `expires`, falscher `keyid`,
      fehlender Content-Digest, Signature-Base-Mismatch, alg-Downgrade, `created` in
      Zukunft, MaxAge, Required Components
- [x] Content-Digest-Vektoren aus RFC 9530
- [x] Property-based Tests (FsCheck): beliebige Header-Kombinationen ergeben
      deterministische Signature Base

### Akzeptanzkriterien

- [x] 100 % der RFC 9421 Appendix-B-Vektoren grün (116 Tests insgesamt)
- [x] Package baut ohne GNAP-Abhängigkeiten (eigenständig veröffentlichbar)
- [ ] Mutation Score (Stryker.NET) ≥ 90 % auf `SignatureBaseBuilder` und Verifier
      (Stryker-Lauf steht noch aus — geplant mit Phase 6 CI-Ausbau)

> **Hinweis zur Umsetzung:** Der Test-Vektor `test-response` verwendet den
> korrigierten Content-Digest (`mEWX…`) der finalen RFC-Fassung; ältere Drafts
> enthielten dort einen veralteten Wert, der nicht zur B.2.4-Signatur passt.

---

## Phase 1 — GNAP Core Primitives

**Ziel:** Package `Gnap.Core` mit allen protokollneutralen Bausteinen, die Client,
AS und RS gemeinsam nutzen.

### Aufgaben

- [x] **JWK-Handling:** Parsing/Serialisierung von JWK (EC, OKP/Ed25519, RSA),
      Thumbprint (RFC 7638), Konvertierung zu/von `System.Security.Cryptography`-Typen
      (`JsonWebKey` inkl. Mapping auf Phase-0-`SignatureAlgorithm`)
- [x] **Key Proofing (RFC 9635 §7.3):**
  - [x] `httpsig` — Anbindung an Phase 0 (`HttpSigKeyProofer` / `HttpSigKeyProofValidator`
        mit Content-Digest-Prüfung, `tag="gnap"`, `created`-Fenster, Nonce-Replay-Schutz
        via `INonceStore`)
  - [x] Proofing-Abstraktion `IKeyProofer` / `IKeyProofValidator` (erweiterbar für
        `mtls`, `jwsd`, `jws`)
- [x] **Interaction Finish Hash (RFC 9635 §4.2.3):**
      `hash = base64url(H(client_nonce + "\n" + as_nonce + "\n" + interact_ref + "\n" + grant_endpoint_url))`
      mit Hash-Agilität (`sha-256` Default, IANA Named Information Registry;
      sha-384/512 immer, sha3-256/384/512 plattformabhängig)
- [x] **Access Token Model:** Wert, `label`, `access` (Array aus Strings und
      strukturierten Objekten), `expires_in`, `key`-Binding (bound/bearer), Flags (`durable`),
      Token-Management (`manage` mit eigenem Access Token)
- [x] **Strukturierte Access Requests (RFC 9635 §8):** `type`, `actions`, `locations`,
      `datatypes`, `identifier`, `privileges` — inkl. Referenz-Strings und
      API-spezifischer Zusatzfelder
- [x] **Interaction Model:** `start` (`redirect`, `app`, `user_code`, `user_code_uri`,
      auch Objekt-Form für Extensions), `finish` (`redirect`, `push`), Nonces,
      Callback-URIs, `hints`/`ui_locales`
- [x] **Fehler-Modell (RFC 9635 §3.6):** `error`-Codes als Typen (`GnapErrorCode` mit
      allen 13 registrierten Codes), String- und Objekt-Form
- [x] **JSON-Serialisierung:** `System.Text.Json` Source Generators für alle Modelle
      (AOT-fähig, trimming-safe), Polymorphie (Referenz vs. Objekt, Objekt vs. Array)
      via Converter
- [x] **Beispiel-App & Doku:** `examples/GnapCore.Demo` (JWKs/Thumbprints, Modelle,
      Proofing inkl. Replay-/Tamper-Abwehr, Finish-Hash, Live-Grant-Flow gegen
      Mini-AS im Prozess) + `docs/gnap-for-dummies.md` (englischer
      Plain-Language-Guide analog zur Phase-0-Doku)

### Tests

- [x] JWK Roundtrip (parse → export → parse) für alle Key-Typen, Thumbprint-Vektoren
      aus RFC 7638 (RSA) und RFC 8037 (Ed25519)
- [x] Key Proof positiv/negativ (falscher Key, manipulierter Body, Replay, fehlender/falscher
      `tag`, verbotener `alg`-Parameter, veraltete Signatur, `keyid`-Mismatch)
- [x] Finish-Hash-Vektoren (sha-256- und sha3-512-Vektoren aus RFC 9635 §4.2.3)
- [x] JSON Serialization Roundtrip für alle Modelle mit Source Generators,
      inkl. Unknown-Member-Toleranz (Forward Compatibility)

### Akzeptanzkriterien

- [x] Alle Modelle bilden RFC 9635 §2–§8 vollständig ab (67 Tests in `Gnap.Core.Tests`)
- [x] Kein Reflection-basiertes JSON (Source Generators only); `IsAotCompatible`
      aktiviert, AOT-Analyzer warnungsfrei (Native-AOT-Publish-Smoke-Test folgt mit
      Phase 6 CI-Ausbau)
- [x] Key-Proof-Negativtests decken alle Manipulationsklassen ab

---

## Phase 2 — Client Library

**Ziel:** Package `Gnap.Client` — vollständiger GNAP-Client, der gegen beliebige
RFC-9635-konforme AS funktioniert.

### Aufgaben

- [ ] **AS-Discovery:** `.well-known/gnap-as-rs` (RFC 9635 §9.1), Caching der
      AS-Metadaten
- [ ] **Grant Request Flow:** `POST /tx` mit signiertem Request (httpsig aus Phase 0),
      `client`-Objekt (Key by value/reference), `access_token`, `subject`, `interact`
- [ ] **Interaction Handling:**
  - [ ] Redirect-Flow (Browser-Start, `interact.redirect`)
  - [ ] User Code / User Code URI (Device-Flow-artig)
  - [ ] Finish-Callback (`redirect`-Empfang inkl. `hash`-Verifikation, `push`-Empfang)
- [ ] **Continuation:** `POST {continue.uri}` mit Continuation Access Token,
      `interact_ref`, Polling mit `wait`-Respektierung und Backoff
- [ ] **Token Management:** Token Rotation (`POST` auf Token-Management-URI),
      Revocation (`DELETE`), automatischer Refresh bei Expiry, Key Rotation des Clients
- [ ] **API-Design:** `GnapClient` (High-Level, `await client.RequestAccessAsync(...)`)
      + Low-Level-Bausteine; `IHttpClientFactory`-Integration; DI-Extensions
      `services.AddGnapClient(...)`

### Tests

- [ ] **Mock AS mit WireMock.Net:** vollständiger Grant → Interaction → Continuation
      → Token Flow als Integrationstest
- [ ] Error Scenarios: `invalid_request`, `invalid_client`, `user_denied`,
      `too_fast` (Polling), `unknown_interaction`, HTTP 5xx mit Retry
- [ ] Token Expiry → automatischer Refresh/Rotation
- [ ] Finish-Hash-Verifikation: gültig, manipuliert, fehlend
- [ ] Signatur jedes ausgehenden Requests wird vom Mock verifiziert (Phase-0-Verifier
      im Test-Server)

### Akzeptanzkriterien

- ✅ Kompletter Redirect-Flow gegen Mock AS grün (inkl. Hash-Verifikation)
- ✅ Alle RFC-9635-Fehlercodes werden typisiert behandelt (keine Silent Failures)
- ✅ Client läuft ohne ASP.NET-Core-Abhängigkeit (Console-App-fähig)

---

## Phase 3 — Authorization Server

**Ziel:** AS-Framework in `Gnap.AspNetCore` — als einbettbare ASP.NET-Core-Komponente
mit pluggbarer Policy und Storage.

### Aufgaben

- [ ] **Grant Endpoint (`POST /tx`):** Request-Parsing, Signatur-/Key-Proof-Verifikation,
      Client-Identifikation (Key by value/reference), Grant-State-Machine
      (`processing`, `pending`, `approved`, `finalized`, `revoked`)
- [ ] **Interaction Flows:**
  - [ ] Redirect-Endpoint mit Session-Bindung
  - [ ] Consent UI (Razor-Pages-Referenzimplementierung, austauschbar via Interface)
  - [ ] User Code Eingabe-Endpoint
  - [ ] Finish: Redirect mit `interact_ref` + `hash`, Push-Notification
- [ ] **Continuation Endpoint:** Continuation-Token-Verifikation (key-bound),
      `interact_ref`-Abgleich, Finish-Hash-Erzeugung, `wait`-Steuerung, Einmaligkeit
      von `interact_ref`
- [ ] **Token Issuance:** key-bound Tokens (Default) und Bearer-Tokens, Token-Format
      pluggable (`ITokenFormat`: opaque + Referenz-Store, optional JWT), Multi-Token-Responses
      (`access_token` als Array), Token-Management-URIs
- [ ] **Policy Engine:** `IGrantPolicy` — entscheidet pro Request über
      `approve/deny/require-interaction`, Zugriff auf Client-Identität, angefragte
      Rechte, Subject-Informationen
- [ ] **Storage-Abstraktion:** `IGrantStore`, `ITokenStore`, `IClientKeyStore`
      (In-Memory-Referenz + EF-Core-Beispiel)
- [ ] **RS-Facing Features (Vorbereitung Phase 4):** Introspection Endpoint
      (RFC 9767 §3.3) mit RS-Authentifizierung

### Tests

- [ ] **End-to-End mit echtem Client aus Phase 2** (`WebApplicationFactory`):
      kompletter Flow inkl. Consent-Simulation
- [ ] **Security Tests:**
  - [ ] Replay eines signierten Requests (Nonce/created-Fenster) → abgelehnt
  - [ ] Unsolicited Continuation (fremdes/abgelaufenes Continuation Token) → abgelehnt
  - [ ] Manipulierter `interact_ref` → abgelehnt, Grant bleibt unberührt
  - [ ] Doppelte Continuation nach Finish → `unknown_interaction`
  - [ ] Key-Mismatch zwischen Grant Request und Continuation → abgelehnt
- [ ] **Policy Tests:** deterministische Entscheidungen, Deny-by-Default
- [ ] State-Machine-Tests: illegale Übergänge unmöglich

### Akzeptanzkriterien

- ✅ Phase-2-Client absolviert alle Flows gegen den AS ohne Sonderbehandlung
- ✅ Alle Security-Negativtests grün, Fehlerantworten ohne Informationsleck
- ✅ Policy und Storage vollständig über DI austauschbar

---

## Phase 4 — Resource Server Middleware

**Ziel:** RS-Unterstützung in `Gnap.AspNetCore` — geschützte APIs mit
GNAP-Token-Verifikation in einer Zeile Middleware.

### Aufgaben

- [ ] **Token-Verifikations-Middleware:** `Authorization: GNAP <token>` Parsing,
      Key-Bound-Token → Signatur-Verifikation des Requests (Phase 0) gegen den an
      das Token gebundenen Key, Bearer-Token-Support (opt-in)
- [ ] **RS-Discovery (RFC 9767):** `.well-known`-Metadaten des RS,
      `resource_server`-Registrierung beim AS
- [ ] **Token Introspection (RFC 9767 §3.3):** Introspection-Client mit
      signierten Requests, Response-Caching (TTL ≤ Token-Restlaufzeit, negative
      Caches kurz), lokale Verifikation als Alternative (`ITokenFormat` aus Phase 3)
- [ ] **Autorisierung:** Mapping von `access`-Rechten auf ASP.NET Core
      Authorization Policies (`RequireGnapAccess("read-balances")`),
      `HttpContext`-Feature mit Token-Metadaten
- [ ] **Fehlerverhalten:** `WWW-Authenticate: GNAP`-Header, RFC-konforme
      401/403-Semantik

### Tests

- [ ] Signierte Requests: gültig / falscher Key / manipulierter Body / fehlende
      Signatur bei key-bound Token
- [ ] Abgelaufene und revozierte Tokens (Introspection-Pfad und lokaler Pfad)
- [ ] Introspection-Caching: Hit/Miss/Expiry, Cache-Invalidierung nach Revocation
- [ ] **Integration: Client → AS → RS → Protected Resource** — der vollständige
      Vier-Parteien-Flow in einem Test (alle eigenen Komponenten)

### Akzeptanzkriterien

- ✅ End-to-End-Flow über alle vier Rollen grün
- ✅ Key-bound Token ohne gültige Request-Signatur wird **immer** abgelehnt
- ✅ RS funktioniert gegen den eigenen AS sowohl via Introspection als auch lokal

---

## Phase 5 — Interoperability Testing

**Ziel:** Nachgewiesene Interoperabilität mit unabhängigen GNAP-Implementierungen.

**Referenz-Implementierungen:**
- **Rafiki** (Interledger, TypeScript) — produktiver GNAP AS (Open Payments)
- **aaronpk/gnap-client-php** — unabhängiger PHP-Client

### Aufgaben

- [ ] **Docker-Compose-Setups:**
  - [ ] `interop/rafiki/` — Rafiki AS + .NET Client
  - [ ] `interop/php-client/` — PHP Client + .NET AS
- [ ] Interop-Testsuite als eigenes xUnit-Projekt mit `docker compose`-Fixture
- [ ] **RFC 9635 Conformance Checklist:** Markdown-Matrix (MUST/SHOULD/MAY ×
      Client/AS/RS) mit Verweis auf den jeweiligen Test
- [ ] Abweichungen/Bugs dokumentieren, ggf. Issues upstream melden

### Tests

- [ ] **.NET Client → Rafiki AS:** Grant Request, Interaction, Continuation,
      Token-Nutzung gegen Open-Payments-Ressource
- [ ] **PHP Client → .NET AS:** vollständiger Redirect-Flow
- [ ] **HTTP-Message-Signature-Kompatibilität:** Kreuzweise Signatur-Verifikation
      (unsere Signaturen ↔ fremde Verifier und umgekehrt), Ed25519 + ECDSA
- [ ] Edge Cases: unterschiedliche `content-digest`-Algorithmen, Header-Casing,
      Query-Encoding

### Akzeptanzkriterien

- ✅ Beide Cross-Implementation-Flows laufen reproduzierbar in CI (nightly)
- ✅ Conformance-Checklist: alle MUST-Anforderungen erfüllt oder mit Begründung
      dokumentiert

---

## Phase 6 — Polish, Docs & Release

**Ziel:** Veröffentlichungsreife: Dokumentation, Qualitätssicherung, NuGet-Release.

### Aufgaben

- [ ] **Dokumentation:**
  - [ ] README pro Package + Repo-README mit Quickstart (Client in 10 Zeilen)
  - [ ] XML Docs auf allen Public APIs (`<PropertyGroup>`-Enforcement: CS1591 als Error)
  - [ ] Architektur-Diagramme (Mermaid: Komponenten, Sequenzen für alle Flows)
  - [ ] Threat-Model-Dokument (STRIDE-Kurzform) + Security-Hinweise für Betreiber
- [ ] **NuGet-Release (4 Packages):**
  - [ ] `Gnap.HttpMessageSignatures`, `Gnap.Core`, `Gnap.Client`, `Gnap.AspNetCore`
  - [ ] Source Link, deterministische Builds, SemVer, signierte Packages,
        `PackageReadmeFile`
- [ ] **CI/CD (GitHub Actions):**
  - [ ] Build + Test-Matrix (Linux/Windows), Coverage-Gate
  - [ ] CodeQL (C#) auf jedem PR
  - [ ] Nightly Interop-Runs (Phase 5)
  - [ ] Release-Workflow: Tag → Pack → Push nach NuGet.org
- [ ] **Stryker.NET Mutation Testing** für Krypto-Logik (Phase 0 + Key Proofing)
      als CI-Gate
- [ ] **Example Apps** mit Docker-Compose:
  - [ ] `examples/console-client` — CLI-Client mit User Code Flow
  - [ ] `examples/web-client` — ASP.NET Core Web-App mit Redirect-Flow
  - [ ] `examples/authorization-server` — AS mit Consent UI
  - [ ] `examples/resource-server` — geschützte Minimal-API

### Akzeptanzkriterien

- ✅ `docker compose up` in `examples/` ergibt einen vollständigen lauffähigen
      GNAP-Stack
- ✅ Alle 4 Packages auf NuGet.org, Source Link funktioniert im Debugger
- ✅ CI vollständig grün inkl. CodeQL, Mutation-Gate und Nightly Interop

---

## Test-Strategie

| Ebene | Tool | Einsatz |
|-------|------|---------|
| Unit | xUnit + FluentAssertions | Krypto, Serialisierung, Validierung |
| Mock HTTP | WireMock.Net | AS/Client/RS Interaktionen |
| Integration | `WebApplicationFactory` | End-to-End ASP.NET Core |
| Interop | Docker-Compose + xUnit | Gegen Rafiki & PHP Client |
| Mutation | Stryker.NET | Krypto-Logik Survive-Mutations |
| Security | CodeQL + manuelle Checklist | OWASP-konforme Fehlerbehandlung |

**Grundsätze:**

- Test-Vektoren aus RFCs sind unveränderliche Fixtures (eigene Dateien unter
  `tests/vectors/`).
- Jeder Security-relevante Codepfad hat mindestens einen Negativtest.
- Interop-Tests laufen nightly, nicht pro PR (Laufzeit/Netzwerk), sind aber
  Release-Blocker.

---

## Package-Übersicht

| Package | Inhalt | Abhängigkeiten |
|---------|--------|----------------|
| `Gnap.HttpMessageSignatures` | RFC 9421 + RFC 9530, Middleware, `DelegatingHandler` | `BouncyCastle.Cryptography` (nur für Ed25519) |
| `Gnap.Core` | JWK, Key Proofing, Modelle, Finish Hash | `Gnap.HttpMessageSignatures` |
| `Gnap.Client` | GNAP-Client, Discovery, Flows, Token Management | `Gnap.Core` |
| `Gnap.AspNetCore` | AS-Framework + RS-Middleware | `Gnap.Core`, ASP.NET Core |

---

## Quellen

1. The GNAPathon — https://justinsecurity.medium.com/the-gnapathon-57ee110508ac
2. RFC 9421: HTTP Message Signatures — https://www.rfc-editor.org/rfc/rfc9421.pdf
3. forcebit/http-message-signatures-rfc9421-go — https://pkg.go.dev/github.com/forcebit/http-message-signatures-rfc9421-go
4. skillmonster/http-message-signature (PHP) — https://packagist.org/packages/skillmonster/http-message-signature
5. yaronf/httpsign (Go) — https://github.com/yaronf/httpsign
6. GNAP: Grant Negotiation and Authorization Protocol Explained — https://www.youtube.com/watch?v=4XZ7UtYVu00
7. RFC 9635: Grant Negotiation and Authorization Protocol — http://rfc.nop.hu/rfc9xxx/rfc9635.pdf
8. authlete/http-message-signatures (Java) — https://github.com/authlete/http-message-signatures
9. Verification of HTTP Message Signatures (Takahiko Kawasaki) — https://darutk.medium.com/verification-of-http-message-signatures-501bbdc7dfec
10. Understanding HTTP message signatures — https://victoronsoftware.com/posts/http-message-signatures/
11. pyauth/http-message-signatures (Python) — https://github.com/pyauth/http-message-signatures
12. GNAP — oauth.net — https://oauth.net/gnap/
13. Authorizing Payments with GNAP & Open Payments — https://www.youtube.com/watch?v=_T9bdhcOOKU
14. IETF RFC 9635 — GNAP — NETEVO — https://netevo.com.au/resources/ietf-rfc-9635-gnap/
15. RFC 9635 Diskussion — https://lobste.rs/s/e1gujd/rfc_9635_grant_negotiation
16. RFC 9635 Datatracker — https://datatracker.ietf.org/doc/rfc9635/

Weitere normative Referenzen: RFC 9767 (GNAP Resource Server Connections),
RFC 9530 (Digest Fields), RFC 8941 (Structured Field Values), RFC 7638 (JWK Thumbprint).
