#!/bin/bash
# Verify a Paraph attestation using OpenSSL — no Node.js required.
#
# Dependencies: openssl (3.0+), jq, python3, curl
#
# Usage:
#   ./verify.sh <signature>                              — fetch record and key from GitHub
#   ./verify.sh <record.json> <public-key.jwk> [data-file]
#
#   signature       : base64url signature from an attestation record
#   record.json     : attestation JSON from the API or this repo
#   public-key.jwk  : public key from keys/ matching the record's key_id
#   data-file       : (optional) original data — confirms sha256 matches record
#
# Exit codes: 0 = valid, 1 = invalid or error

set -euo pipefail

PARAPH_REPO="${PARAPH_REPO:-attestations}"
GITHUB_RAW="https://raw.githubusercontent.com/paraph-cc/${PARAPH_REPO}/main"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Argument handling: single signature arg → fetch record + key from GitHub.
# ---------------------------------------------------------------------------
if [ $# -eq 1 ]; then
  SIG="${1}"

  SIG_HEX=$(python3 - <<EOF
import base64
sig = "$SIG"
pad = (4 - len(sig) % 4) % 4
print(base64.b64decode(sig.replace('-', '+').replace('_', '/') + '=' * pad).hex())
EOF
)

  ATTEST_PATH="attestations/${SIG_HEX:0:2}/${SIG_HEX:2:2}/${SIG_HEX}.json"

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
  DATAFILE=""
else
  RECORD="${1:-}"
  PUBKEY="${2:-}"
  DATAFILE="${3:-}"

  if [ -z "$RECORD" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: verify.sh <signature>" >&2
    echo "       verify.sh <record.json> <public-key.jwk> [data-file]" >&2
    exit 1
  fi
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
# 3. Decode base64url signature to raw bytes.
# ---------------------------------------------------------------------------
python3 - <<EOF > "$TMPDIR/sig.bin"
import base64, sys
sig = "$SIGNATURE"
pad = (4 - len(sig) % 4) % 4
sys.stdout.buffer.write(base64.b64decode(sig.replace('-', '+').replace('_', '/') + '=' * pad))
EOF

# ---------------------------------------------------------------------------
# 4. Optionally verify the data file hash.
# ---------------------------------------------------------------------------
if [ -n "$DATAFILE" ]; then
  ACTUAL=$(openssl dgst -sha256 -hex "$DATAFILE" | awk '{print $2}')
  if [ "$ACTUAL" = "$SHA256" ]; then
    echo "ok  data hash matches record"
  else
    echo "INVALID — data hash mismatch" >&2
    echo "  record.sha256 : $SHA256" >&2
    echo "  file sha256   : $ACTUAL" >&2
    exit 1
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
  echo "ok  signature valid"
  echo "    key_id    : $(jq -r '.key_id' "$RECORD")"
  echo "    timestamp : $TIMESTAMP  ($ISO)"
  echo "    sha256    : $SHA256"
  exit 0
else
  echo "INVALID — signature does not verify" >&2
  exit 1
fi
