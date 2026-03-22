#!/bin/bash
# Verify a Paraph attestation using OpenSSL — no Node.js required.
#
# Dependencies: openssl (3.0+), jq, python3, curl
#
# Usage:
#   ./verify.sh <signature> [data-file]               — fetch record and key from GitHub
#   ./verify.sh <record.json> <public-key.jwk> [data-file]
#
#   data can also be piped via stdin instead of passing a data-file
#
#   signature       : base64url signature from an attestation record
#   record.json     : attestation JSON from the API or this repo
#   public-key.jwk  : public key from keys/ matching the record's key_id
#   data-file       : original data — confirms sha256 matches record
#
# Environment:
#   PARAPH_REPO     : override the GitHub repo name (default: attestations)
#
# Exit codes: 0 = valid, 1 = invalid or error

set -euo pipefail

PARAPH_REPO="${PARAPH_REPO:-${GITHUB_REPO:-attestations}}"
GITHUB_RAW="https://raw.githubusercontent.com/paraph-cc/${PARAPH_REPO}/main"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Argument handling.
# If arg1 is not an existing file, treat it as a base64url signature and
# fetch the attestation record and public key from GitHub.
# ---------------------------------------------------------------------------
DATAFILE=""

if [ $# -eq 0 ]; then
  echo "Usage: verify.sh <signature> [data-file]" >&2
  echo "       verify.sh <record.json> <public-key.jwk> [data-file]" >&2
  exit 1
fi

if [ ! -f "${1}" ]; then
  # Signature mode
  SIG="${1}"
  DATAFILE="${2:-}"

  ATTEST_PATH="attestations/${SIG:0:2}/${SIG:2:2}/${SIG}.json"

  echo "fetching attestation..." >&2
  if ! curl -sf "$GITHUB_RAW/$ATTEST_PATH" -o "$TMPDIR/record.json"; then
    echo "error: attestation not found on GitHub ($ATTEST_PATH)" >&2
    exit 1
  fi

  KEY_ID=$(jq -r '.key_id' "$TMPDIR/record.json")

  echo "fetching public key $KEY_ID..." >&2
  if ! curl -sf "$GITHUB_RAW/keys/${KEY_ID}.jwk" -o "$TMPDIR/pubkey.jwk"; then
    echo "error: public key '$KEY_ID' not found on GitHub" >&2
    exit 1
  fi

  RECORD="$TMPDIR/record.json"
  PUBKEY="$TMPDIR/pubkey.jwk"
else
  # File mode
  RECORD="${1}"
  PUBKEY="${2:-}"
  DATAFILE="${3:-}"

  if [ -z "$PUBKEY" ]; then
    echo "Usage: verify.sh <signature> [data-file]" >&2
    echo "       verify.sh <record.json> <public-key.jwk> [data-file]" >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Accept piped stdin as data if no data-file was given. Data is required.
# ---------------------------------------------------------------------------
if [ -z "$DATAFILE" ] && [ ! -t 0 ]; then
  cat > "$TMPDIR/stdin.bin"
  DATAFILE="$TMPDIR/stdin.bin"
fi

if [ -z "$DATAFILE" ]; then
  echo "error: data file required — pass your original file or pipe it via stdin" >&2
  echo "  verify.sh <signature> <data-file>" >&2
  echo "  cat <data-file> | verify.sh <signature>" >&2
  exit 1
fi

TIMESTAMP=$(jq -r '.timestamp' "$RECORD")
SHA256=$(jq    -r '.sha256'    "$RECORD")
SIGNATURE=$(jq -r '.signature' "$RECORD")
KEY_X=$(jq     -r '.x'         "$PUBKEY")

# ---------------------------------------------------------------------------
# 1. Convert Ed25519 JWK public key to PEM (SubjectPublicKeyInfo / SPKI).
#    DER structure: fixed 12-byte prefix || 32-byte public key scalar.
#    Prefix hex: 302a300506032b6570032100
# ---------------------------------------------------------------------------
python3 - <<EOF > "$TMPDIR/pub.pem"
import base64

x = "$KEY_X"
pad = (4 - len(x) % 4) % 4
x_bytes = base64.b64decode(x.replace('-', '+').replace('_', '/') + '=' * pad)

spki = bytes.fromhex('302a300506032b6570032100') + x_bytes
pem  = base64.encodebytes(spki).decode().strip()

print('-----BEGIN PUBLIC KEY-----')
print(pem)
print('-----END PUBLIC KEY-----')
EOF

# ---------------------------------------------------------------------------
# 2. Reconstruct the signed payload: uint64 big-endian timestamp || sha256.
# ---------------------------------------------------------------------------
python3 - <<EOF > "$TMPDIR/payload.bin"
import struct, sys
sys.stdout.buffer.write(struct.pack('>Q', $TIMESTAMP) + bytes.fromhex('$SHA256'))
EOF

# ---------------------------------------------------------------------------
# 3. Decode hex signature to raw bytes.
# ---------------------------------------------------------------------------
python3 - <<EOF > "$TMPDIR/sig.bin"
import sys
sys.stdout.buffer.write(bytes.fromhex('$SIGNATURE'))
EOF

# ---------------------------------------------------------------------------
# 4. Verify the data file hash matches the record.
# ---------------------------------------------------------------------------
ACTUAL=$(openssl dgst -sha256 -hex "$DATAFILE" | awk '{print $2}')
if [ "$ACTUAL" != "$SHA256" ]; then
  echo "INVALID — data hash mismatch" >&2
  echo "  record.sha256 : $SHA256" >&2
  echo "  file sha256   : $ACTUAL" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 4b. Verify RFC 3161 TSA timestamp if present in record.
#     openssl ts -verify recomputes sha256(data) and checks it matches the TSR.
#     Set TSA_CA_FILE to a PEM file for full chain verification.
# ---------------------------------------------------------------------------
if jq -e '.tsr' "$RECORD" > /dev/null 2>&1; then
  python3 - <<EOF > "$TMPDIR/tsa.tsr"
import base64, sys
sys.stdout.buffer.write(base64.b64decode('$(jq -r '.tsr' "$RECORD")'))
EOF

  # Find a CA bundle — TSA_CA_FILE overrides, then try system defaults
  TSA_CA="${TSA_CA_FILE:-}"
  if [ -z "$TSA_CA" ]; then
    for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
      if [ -f "$f" ]; then TSA_CA="$f"; break; fi
    done
  fi

  TSA_OPTS=(-verify -in "$TMPDIR/tsa.tsr" -data "$DATAFILE")
  [ -n "$TSA_CA" ] && TSA_OPTS+=(-CAfile "$TSA_CA")

  TSA_TIME=$(openssl ts -reply -in "$TMPDIR/tsa.tsr" -text 2>/dev/null \
    | grep 'Time stamp:' | sed 's/.*Time stamp: //' || echo "unknown")

  if openssl ts "${TSA_OPTS[@]}" 2>/dev/null; then
    echo "ok  RFC 3161 timestamp verified  ($TSA_TIME)"
  else
    echo "warn RFC 3161 timestamp present but chain not verified" >&2
    echo "     timestamp : $TSA_TIME" >&2
    echo "     set TSA_CA_FILE=/path/to/tsa-root.pem for full chain verification" >&2
  fi
fi

# ---------------------------------------------------------------------------
# 5. Verify the Ed25519 signature with OpenSSL.
# ---------------------------------------------------------------------------
if openssl pkeyutl -verify -pubin \
    -inkey   "$TMPDIR/pub.pem" \
    -sigfile "$TMPDIR/sig.bin" \
    -in      "$TMPDIR/payload.bin" 2>/dev/null; then
  ISO=$(python3 -c "from datetime import datetime, timezone; \
    print(datetime.fromtimestamp($TIMESTAMP / 1000, tz=timezone.utc).isoformat())")
  echo "ok  data matches record"
  echo "ok  signature valid"
  echo "    key_id    : $(jq -r '.key_id' "$RECORD")"
  echo "    timestamp : $TIMESTAMP  ($ISO)"
  echo "    sha256    : $SHA256"
  exit 0
else
  echo "INVALID — signature does not verify" >&2
  exit 1
fi
