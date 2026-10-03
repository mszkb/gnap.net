# Changelog

All notable changes to the gnap.net packages are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the packages use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). All five packages are
released together with the same version.

## [Unreleased]

First public release, planned as `0.1.0`.

### Added

- **Gnap.HttpMessageSignatures** — RFC 9421 HTTP Message Signatures: signature base
  canonicalization (all derived components, `sf`/`key`/`bs`/`tr`/`req` parameters,
  RFC 8941 structured fields), signing and verification with Ed25519, ECDSA P-256/P-384,
  RSA-PSS SHA-512, RSA v1.5 SHA-256 and HMAC-SHA256, multi-signature verification with
  time windows, required components and nonce replay protection, RFC 9530
  `Content-Digest`, PEM key loading and an `HttpClient` `DelegatingHandler`. Verified
  against all RFC 9421 Appendix B test vectors.
- **Gnap.HttpMessageSignatures.AspNetCore** — middleware verifying signatures and
  content digests of incoming requests.
- **Gnap.Core** — JSON Web Keys with RFC 7638 thumbprints, `httpsig` key proofing,
  interaction finish hash, `Authorization: GNAP` presentation and source-generated JSON
  models for grant requests and responses (Native AOT compatible).
- **Gnap.Client** — GNAP client: discovery, signed grant requests, redirect, push and
  user-code interaction with finish-hash verification, continuation and polling, token
  rotation, revocation and key rotation, an `HttpClient` handler for resource servers,
  DI integration.
- **Gnap.AspNetCore** — embeddable GNAP authorization server (grant, continuation,
  interaction, token management, RFC 9767 introspection and resource registration,
  discovery; pluggable policy, stores and token formats) and resource server middleware
  (key-bound token verification, introspection with caching, JWT and co-hosted
  validation, `RequireGnapAccess` policies).
- Interoperability verified against Rafiki (Interledger), gnap-client-php and two
  JavaScript HTTP signature libraries.
- NuGet packaging with Source Link, deterministic builds, symbol packages and package
  READMEs; CI with coverage gate, CodeQL, mutation testing and a tag-driven release
  workflow.

[Unreleased]: https://github.com/mszkb/gnap.net/commits/main
