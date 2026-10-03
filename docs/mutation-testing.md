# Mutation testing (Stryker.NET)

Line coverage only says that a test *executed* a line; mutation testing checks
that a test would actually *fail* if that line were wrong. [Stryker.NET](https://stryker-mutator.io/docs/stryker-net/introduction/)
introduces small faults ("mutants") into the code — `<` becomes `<=`, a `throw`
is removed, a string becomes empty — and runs the test suite against each one.
A mutant that no test notices *survives* and points at a gap in the tests.

## Scope

Mutation testing is focused on the security-critical core of
`Gnap.HttpMessageSignatures` (see [`stryker-config.json`](../stryker-config.json)):

| File | Why |
| --- | --- |
| `SignatureBaseBuilder.cs` | Canonical signature base — any deviation breaks interop or lets tampering through |
| `HttpMessageVerifier.cs` | Timestamp window, alg-downgrade, required components, replay checks |
| `ContentDigest.cs` | Body integrity (RFC 9530), streaming size limit |
| `SignatureAlgorithm.cs` | Algorithm names and key validation |

The test project is `tests/Gnap.HttpMessageSignatures.Tests`.

## Running it

Stryker is pinned as a local dotnet tool in `.config/dotnet-tools.json`:

```bash
dotnet tool restore
dotnet stryker            # reads stryker-config.json, takes ~3 minutes on 4 cores
```

The HTML report is written to `StrykerOutput/<timestamp>/reports/mutation-report.html`
(`StrykerOutput/` is git-ignored). The run fails (non-zero exit code) when the
score drops below 90 % (`thresholds.break`).

> **Note:** the `progress` reporter of Stryker 5 crashes on narrow or
> non-interactive terminals (CI logs, redirected output), so the config uses
> the `cleartext` reporter instead.

The GitHub Actions workflow [`mutation.yml`](../.github/workflows/mutation.yml)
runs the same configuration nightly and on demand (`workflow_dispatch`) and
uploads the report as an artifact.

## Current result

| File | Killed | Survived | Score |
| --- | ---: | ---: | ---: |
| `SignatureBaseBuilder.cs` | 98 | 0 | 100 % |
| `HttpMessageVerifier.cs` | 42 | 0 | 100 % |
| `ContentDigest.cs` | 39 (incl. 1 timeout) | 0 | 100 % |
| `SignatureAlgorithm.cs` | 34 | 0 | 100 % |
| **Total** | **213** | **0** | **100 %** |

The first run (before targeted tests were added) scored 73.6 % overall, with
`SignatureBaseBuilder` at 60.6 % and `HttpMessageVerifier` at 84.8 %. The
surviving mutants were mostly untested error paths (missing method/URI/status,
`req` on a request, unknown derived components, `sf`/`key` on lists and items),
exact timestamp-window boundaries (`created` exactly at the clock-skew limit),
nonce retention without a bounded window, and the streaming read budget of
`ContentDigest.ValidateAsync` with short reads.

Mutants that fail to compile ("CompileError") are discarded by Stryker and do
not count towards the score.

## Equivalent mutants

A few mutants cannot be detected by any test because they do not change
observable behaviour. They are excluded in the source with a
`// Stryker disable ... : <reason>` comment so the reason stays next to the
code:

| Location | Mutation | Why it is equivalent |
| --- | --- | --- |
| `HttpMessageVerifier.GetNonceExpiry` | `end < expiresEnd` → `<=` | When both instants are equal either branch returns the same value |
| `HttpMessageVerifier.VerifyOneAsync`, `ContentDigest.ValidateAsync` | `ConfigureAwait(false)` → `true` | Only changes the continuation context |
| `ContentDigest.ValidateAsync` (`finally`) | Removing `Dispose()` | Leaks native hash handles, but the result is unchanged |
| `SignatureBaseBuilder.CanonicalizeFieldValue` | Removing the "no line break" fast path | The general path produces the same string |

One equivalent mutant was removed by simplifying the code instead:
`HttpMessageVerifier.ParseDictionaryField` no longer special-cases an absent
field, because the empty string already parses as an empty dictionary.

When adding a new exclusion, keep it as narrow as possible (`disable once` plus
the specific mutator) and always give a reason.
