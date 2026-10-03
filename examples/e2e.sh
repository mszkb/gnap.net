#!/usr/bin/env bash
# End-to-end check of the example GNAP stack (examples/docker-compose.yml): plays the
# resource owner with curl instead of a browser.
#
#   1. console client (user code flow): reads the code from the client's output, enters it at
#      the AS, approves on the consent page, expects the client to print "-> 200".
#   2. web client (redirect flow): /connect -> AS interaction -> consent -> /callback,
#      expects "Access granted" and a 200 from the resource server.
#
# Usage (stack running):  examples/e2e.sh
#   CONSOLE_LOG_CMD  command printing the console client's output
#                    (default: docker compose -f examples/docker-compose.yml logs --no-log-prefix console-client)
#   AS_URL, WEB_URL  default http://localhost:5100, http://localhost:5300
set -euo pipefail

AS_URL="${AS_URL:-http://localhost:5100}"
WEB_URL="${WEB_URL:-http://localhost:5300}"
CONSOLE_LOG_CMD="${CONSOLE_LOG_CMD:-docker compose -f examples/docker-compose.yml logs --no-log-prefix console-client}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# Approves the interaction the browser (cookie jar $1) is on: $2 = consent page URL.
approve() {
  local jar="$1" consent_url="$2"
  local html token interaction
  html="$(curl -sS -b "$jar" -c "$jar" "$consent_url")"
  token="$(grep -o 'name="__RequestVerificationToken" type="hidden" value="[^"]*"' <<<"$html" | sed 's/.*value="//; s/"$//')"
  interaction="$(sed -n 's/.*[?&]interaction=\([^&]*\).*/\1/p' <<<"$consent_url")"
  [ -n "$token" ] || fail "no antiforgery token on $consent_url"
  [ -n "$interaction" ] || fail "no interaction id in $consent_url"
  curl -sS -b "$jar" -c "$jar" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "__RequestVerificationToken=$token" \
    --data-urlencode "Interaction=$interaction" \
    --data-urlencode "UserName=alice" \
    "$AS_URL/consent?handler=Approve"
}

echo "== console client (user code flow)"
code=""
for _ in $(seq 1 90); do
  code="$($CONSOLE_LOG_CMD 2>/dev/null | sed -n 's/.*enter the code: \([A-Z0-9-]*\).*/\1/p' | tail -n 1)" || true
  [ -n "$code" ] && break
  sleep 2
done
[ -n "$code" ] || fail "the console client did not print a user code"
echo "user code: $code"

jar="$work/console.jar"
consent="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' --data-urlencode "user_code=$code" "$AS_URL/gnap/device")"
case "$consent" in */consent\?interaction=*) ;; *) fail "device code entry did not lead to the consent page: '$consent'";; esac
case "$consent" in http*) ;; *) consent="$AS_URL$consent";; esac
approve "$jar" "$consent" >/dev/null

for _ in $(seq 1 60); do
  out="$($CONSOLE_LOG_CMD 2>/dev/null)" || true
  grep -q -- '-> 200' <<<"$out" && break
  grep -q -- '-> [45][0-9][0-9]' <<<"$out" && break
  sleep 2
done
grep -- '->' <<<"$out" || true
grep -q -- '-> 200' <<<"$out" || fail "the console client did not get the resource"
grep -q '"owner":"alice"' <<<"$out" || fail "the resource does not name the approving resource owner"
echo "console client: OK"

echo "== web client (redirect flow)"
jar="$work/web.jar"
interact="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$WEB_URL/connect")"
case "$interact" in "$AS_URL"/gnap/interact/*) ;; *) fail "/connect did not redirect to the AS: '$interact'";; esac
consent="$(curl -sS -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}' "$interact")"
case "$consent" in http*) ;; *) consent="$AS_URL$consent";; esac
callback="$(approve "$jar" "$consent")"
case "$callback" in "$WEB_URL"/callback\?*) ;; *) fail "approval did not redirect to the web client: '$callback'";; esac
page="$(curl -sS -c "$jar" -b "$jar" "$callback")"
grep -q 'Access granted' <<<"$page" || fail "web client: $page"
grep -q '200 OK' <<<"$page" || fail "web client did not get the resource: $page"
echo "web client: OK"
echo "All example flows passed."
