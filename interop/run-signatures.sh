#!/usr/bin/env bash
# Cross-verification of HTTP Message Signatures (Ed25519 + ECDSA P-256) between
# Gnap.HttpMessageSignatures / Gnap.Core and two JavaScript implementations
# (http-message-signatures, @interledger/http-signature-utils). Needs node.
set -euo pipefail
cd "$(dirname "$0")/.."

(cd interop/signatures && npm ci --no-audit --no-fund)

GNAP_INTEROP_NODE_SIGNATURES=1 dotnet test tests/Gnap.Interop.Tests --configuration "${CONFIGURATION:-Release}" \
  --filter "FullyQualifiedName~Signatures" --logger "trx;LogFileName=signatures.trx" --results-directory TestResults/interop \
  --logger "console;verbosity=normal"
