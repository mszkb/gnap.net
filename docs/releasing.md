# Releasing gnap.net

All five packages are versioned and released together by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a version tag is
pushed. Nothing is published by ordinary CI runs.

| Package | Project |
|---|---|
| `Gnap.HttpMessageSignatures` | `src/Gnap.HttpMessageSignatures` |
| `Gnap.HttpMessageSignatures.AspNetCore` | `src/Gnap.HttpMessageSignatures.AspNetCore` (dependency of `Gnap.AspNetCore`) |
| `Gnap.Core` | `src/Gnap.Core` |
| `Gnap.Client` | `src/Gnap.Client` |
| `Gnap.AspNetCore` | `src/Gnap.AspNetCore` |

## Before the first release

> [!WARNING]
> **The package ID `Gnap.Core` is already taken on nuget.org** (versions 1.0.0/1.0.1
> from 2018, owner *infrabel*, project "GNaP.Common" — unrelated to RFC 9635). Package
> IDs are case-insensitive, so `dotnet nuget push` of `Gnap.Core` will be rejected.
> The other four IDs were free when this was written. Decide before tagging:
>
> 1. **Rename the package IDs** (recommended: consistent prefix, e.g. `GnapNet.Core`,
>    `GnapNet.Client`, … for all five). Only `<PackageId>` in the five `.csproj` files
>    needs to change (assembly and namespace names can stay `Gnap.*`); update the
>    package names in the READMEs, `docs/releasing.md` and the package check in
>    `release.yml`.
> 2. Or ask the current owner to transfer the ID (nuget.org → *Contact owners*), or
>    ask nuget.org support if the package is abandoned.
>
> Also consider [reserving the ID prefix](https://learn.microsoft.com/nuget/nuget-org/id-prefix-reservation)
> you choose, so packages get the verified checkmark.

1. **nuget.org account** — sign in at <https://www.nuget.org> (the account or
   organization that will own the packages).
2. **API key** — *Account → API Keys → Create*: scope *Push new packages and package
   versions*, glob pattern matching the package IDs (e.g. `Gnap.*` or `GnapNet.*`),
   expiry 365 days.
3. **GitHub secret** — repository *Settings → Secrets and variables → Actions → New
   repository secret*: name `NUGET_API_KEY`, value the API key. (Or with the GitHub
   CLI: `gh secret set NUGET_API_KEY --repo mszkb/gnap.net`.)
4. **Optional: protect the release** — the publish job runs in the GitHub environment
   `nuget` (created automatically on first use). Under *Settings → Environments →
   nuget* add yourself as a required reviewer and/or move the `NUGET_API_KEY` secret
   into that environment; then every publish waits for approval.

### Alternative: trusted publishing (no long-lived key)

nuget.org supports [trusted publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing)
via GitHub OIDC. To use it instead of an API key: create a trusted publishing policy on
nuget.org (repository `mszkb/gnap.net`, workflow `release.yml`, environment `nuget`),
give the publish job `id-token: write`, add a `NuGet/login@v1` step (with your nuget.org
user name) before the push and pass its `NUGET_API_KEY` output to `dotnet nuget push`
instead of the secret.

## Cutting a release

1. Make sure `main` is green (CI, CodeQL; nightly Interop and Mutation runs are
   release blockers).
2. Optionally do a dry run: *Actions → Release → Run workflow*, version e.g.
   `0.1.0-preview.1`, *publish* unchecked. It builds, tests and packs, checks every
   package (README, symbols, Source Link commit) and uploads them as an artifact you
   can inspect or install from a local feed.
3. Move the `[Unreleased]` entries in [`CHANGELOG.md`](../CHANGELOG.md) under a new
   heading `## [0.1.0] - YYYY-MM-DD`, add the compare link, commit and push to `main`.
4. Tag and push (SemVer 2.0 with a leading `v`; a suffix like `-preview.1` makes a
   prerelease):

   ```bash
   git tag -a v0.1.0 -m "gnap.net 0.1.0"
   git push origin v0.1.0
   ```

5. The *Release* workflow builds and tests the tagged commit with `Version=0.1.0`,
   packs, pushes `*.nupkg` and the matching `*.snupkg` symbol packages to nuget.org
   (`--skip-duplicate`, so re-running is safe) and creates the GitHub release with the
   packages attached.
6. After nuget.org has indexed the packages (a few minutes), check a package page:
   README rendered, *Source Link: ✓* and *Deterministic: ✓* in the package health
   section, and stepping into the library code in a debugger works.
7. After the first release, set `<PackageValidationBaselineVersion>` in
   `Directory.Build.props` to the released version so later builds fail on breaking
   API changes, and bump `<VersionPrefix>` to the next planned version.

If a release is broken, **unlist** the version on nuget.org (packages cannot be
deleted) and release a new patch version.

## What the build guarantees

Configured in [`Directory.Build.props`](../Directory.Build.props):

- **SemVer** — `VersionPrefix` (local and CI builds: `0.1.0-dev`); the release overrides
  `Version` from the tag.
- **Source Link** — `PublishRepositoryUrl`, `EmbedUntrackedSources`; the repository URL
  and commit are recorded in the `.nuspec` and the PDBs.
- **Deterministic builds** — `Deterministic` plus `ContinuousIntegrationBuild` on GitHub
  Actions (normalized `/_/` source paths).
- **Symbols** — `.snupkg` symbol packages, pushed to the nuget.org symbol server.
- **Package README** — each project's `README.md` is packed as `PackageReadmeFile`.
- **XML docs** — `GenerateDocumentationFile` with warnings as errors, so every public
  API needs documentation (CS1591).
- **Package validation** — `EnablePackageValidation`.

### Package signing

nuget.org repository-signs every package it accepts, so consumers can verify packages
came from nuget.org. Author signing additionally requires a code-signing certificate
from a CA trusted by NuGet; it is not set up. If you obtain one, add a
`dotnet nuget sign artifacts/packages/*.nupkg --certificate-path … --timestamper
http://timestamp.digicert.com` step before the push, with the certificate in a secret,
and register the certificate on your nuget.org account.
