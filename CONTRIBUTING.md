# Contributing to gnap.net

Thanks for your interest! Issues and pull requests are welcome.

## Getting started

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
dotnet build Gnap.sln      # warnings are errors, public APIs need XML docs (CS1591)
dotnet test Gnap.sln       # all unit and integration tests
```

Optional checks that CI also runs:

```bash
# coverage report and gate (line >= 85 %, branch >= 75 %)
dotnet test Gnap.sln --collect:"XPlat Code Coverage" --results-directory TestResults
dotnet tool restore
dotnet reportgenerator -reports:"TestResults/**/coverage.cobertura.xml" -targetdir:TestResults/coverage \
  -reporttypes:TextSummary -assemblyfilters:"+Gnap.*;-Gnap.*.Tests;-Gnap.Interop.Tests"

# packages
dotnet pack build/Gnap.Packages.slnf -c Release -o artifacts/packages

# mutation testing of the signature code (gate 90 %)
dotnet stryker
```

Interoperability tests need Docker, Node.js or PHP; see [docs/interop.md](docs/interop.md).

## Guidelines

- **Tests first for protocol and crypto code.** Every security-relevant code path needs
  a negative test; where an RFC publishes test vectors, they are the fixtures.
- **No home-grown cryptography.** Use `System.Security.Cryptography` (BouncyCastle only
  where .NET lacks a primitive, currently Ed25519).
- **No oracles.** Errors returned to peers stay generic; the concrete reason goes to the
  log.
- **Public API.** Every public type and member needs XML documentation. Keep APIs
  consistent with the existing packages (async methods take a `CancellationToken`,
  options classes for configuration, interfaces for anything pluggable via DI).
- **Docs.** Update the guide under `docs/` and `CHANGELOG.md` (`[Unreleased]`) with
  user-visible changes.
- Keep commits focused and describe *why* in the message.

## Reporting security issues

Please do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## Releasing

Maintainers: see [docs/releasing.md](docs/releasing.md).
