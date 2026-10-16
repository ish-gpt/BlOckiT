#!/usr/bin/env bash
# Creates a self-signed RSA signing certificate for LOCAL TESTING and writes it to .env.
# iOS will install profiles signed with it but label them "Not Verified".
# For production, use a real RSA certificate from a public CA (see README).
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${ENV_FILE:-.env}"

if [ -e "$OUT" ]; then
  echo "$OUT already exists — not overwriting. Delete it first if you want a new dev cert." >&2
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=BlOckiT Dev Signing" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null

# One line per PEM with literal \n, which lib/sign.js expands back into newlines.
oneline() { awk 'NR > 1 { printf "\\n" } { printf "%s", $0 }' "$1"; }

umask 077
{
  printf 'SSL_CERTIFICATE="%s"\n' "$(oneline "$tmp/cert.pem")"
  printf 'SSL_PRIVATE_KEY="%s"\n' "$(oneline "$tmp/key.pem")"
  printf 'SSL_INTERMEDIATE=""\n'
  printf 'ACCESS_CODE=""\n'
} > "$OUT"

echo "Wrote $OUT with a self-signed dev certificate (valid 365 days)."
echo "Restart the server: npm run dev"
