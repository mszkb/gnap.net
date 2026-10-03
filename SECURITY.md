# Security policy

gnap.net implements authorization and cryptographic protocols (GNAP, RFC 9635; HTTP
Message Signatures, RFC 9421). We take vulnerabilities seriously.

## Supported versions

| Version | Supported |
|---|---|
| latest release on nuget.org | yes |
| `main` | yes (fixes land here first) |
| older releases | no — please upgrade |

Before 1.0 there are no long-term support branches; fixes ship in the next release.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
[Security → Report a vulnerability](https://github.com/mszkb/gnap.net/security/advisories/new)
(private vulnerability reporting).

Please include the affected package and version, a description of the issue and its
impact, and a reproduction (a failing test is ideal). We aim to acknowledge reports
within 7 days and to agree on a disclosure date with you; credit is given in the
advisory unless you prefer otherwise.

## Scope

In scope: the packages under `src/` — signature canonicalization and verification,
key proofing, token handling, the authorization server and resource server
middleware. The applications under `examples/` are demos (they use published test
keys and demo policies) and are not meant for production; issues there are welcome
as normal issues.

For the threat model and the configuration operators are responsible for (TLS,
shared nonce stores, rate limiting, resource owner authentication, …) see
[docs/threat-model.md](docs/threat-model.md).
