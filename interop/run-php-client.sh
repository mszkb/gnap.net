#!/usr/bin/env bash
# aaronpk/gnap-client-php -> Gnap.AspNetCore authorization server (redirect flow).
# Fetches the PHP client at a pinned commit, installs its dependencies, applies
# interop/php-client/rfc9635-signatures.patch (see docs/interop.md for why) and
# runs Gnap.Interop.Tests.Php. Needs php (curl, mbstring, openssl) and composer.
set -euo pipefail
cd "$(dirname "$0")/.."

commit="${GNAP_CLIENT_PHP_COMMIT:-177edf0e785027cb0d3f155e92e705bee66da048}"
dir="interop/.cache/gnap-client-php"
if [[ ! -d "$dir/.git" ]]; then
  git clone --quiet https://github.com/aaronpk/gnap-client-php "$dir"
fi
git -C "$dir" checkout --quiet --force "$commit"
# The 2022 lock file pins packages that declare PHP <= 8.1; they run fine on 8.2+.
(cd "$dir" && composer install --no-interaction --no-progress --ignore-platform-reqs)
if [[ "${GNAP_PHP_UNPATCHED:-0}" != "1" ]]; then
  git -C "$dir" apply "$PWD/interop/php-client/rfc9635-signatures.patch"
fi

GNAP_INTEROP_PHP_CLIENT="$PWD/$dir" dotnet test tests/Gnap.Interop.Tests --configuration "${CONFIGURATION:-Release}" \
  --filter "FullyQualifiedName~Php" --logger "trx;LogFileName=php-client.trx" --results-directory TestResults/interop \
  --logger "console;verbosity=normal"
