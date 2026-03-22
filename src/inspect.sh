#!/bin/bash
# Inspect a Paraph attestation record — prints human-readable details.
#
# Dependencies: openssl (3.0+), jq, python3, curl
#
# Usage:
#   ./inspect.sh <signature>          — fetch record from GitHub
#   ./inspect.sh <record.json>        — use local record file
#
# Environment:
#   PARAPH_REPO     : override the GitHub repo name (default: attestations)
#
# Exit codes: 0 = ok, 1 = error

set -euo pipefail

PARAPH_REPO="${PARAPH_REPO:-${GITHUB_REPO:-attestations}}"
GITHUB_RAW="https://raw.githubusercontent.com/paraph-cc/${PARAPH_REPO}/main"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ---------------------------------------------------------------------------
# Resolve the record — either fetch from GitHub or read from a local file.
# ---------------------------------------------------------------------------
if [ $# -eq 0 ]; then
  echo "Usage: inspect.sh <signature>" >&2
  echo "       inspect.sh <record.json>" >&2
  exit 1
fi

if [ ! -f "${1}" ]; then
  SIG="${1}"
  ATTEST_PATH="attestations/${SIG:0:2}/${SIG:2:2}/${SIG}.json"
  echo "fetching attestation..." >&2
  if ! curl -sf "$GITHUB_RAW/$ATTEST_PATH" -o "$TMPDIR/record.json"; then
    echo "error: attestation not found on GitHub ($ATTEST_PATH)" >&2
    exit 1
  fi
  RECORD="$TMPDIR/record.json"
else
  RECORD="${1}"
fi

# ---------------------------------------------------------------------------
# Print record fields.
# ---------------------------------------------------------------------------
KEY_ID=$(jq -r '.key_id' "$RECORD")
TIMESTAMP=$(jq -r '.timestamp' "$RECORD")
SHA256=$(jq -r '.sha256' "$RECORD")
SIGNATURE=$(jq -r '.signature' "$RECORD")
URL=$(jq -r '.url // empty' "$RECORD")
SOURCE_URL=$(jq -r '.source_url // empty' "$RECORD")

ISO=$(python3 -c "from datetime import datetime, timezone; \
  print(datetime.fromtimestamp($TIMESTAMP / 1000, tz=timezone.utc).isoformat())")

echo "attestation"
echo "  key_id    : $KEY_ID"
echo "  timestamp : $TIMESTAMP  ($ISO)"
echo "  sha256    : $SHA256"
echo "  signature : $SIGNATURE"
[ -n "$SOURCE_URL" ] && echo "  source    : $SOURCE_URL"
[ -n "$URL" ]        && echo "  url       : $URL"

# ---------------------------------------------------------------------------
# Print TSA info if tsr field is present.
# ---------------------------------------------------------------------------
if jq -e '.tsr' "$RECORD" > /dev/null 2>&1; then
  python3 - <<EOF > "$TMPDIR/tsa.tsr"
import base64, sys
sys.stdout.buffer.write(base64.b64decode('$(jq -r '.tsr' "$RECORD")'))
EOF

  TSA_TEXT=$(openssl ts -reply -in "$TMPDIR/tsa.tsr" -text 2>/dev/null)

  TSA_TIME=$(echo "$TSA_TEXT"   | grep 'Time stamp:'   | sed 's/.*Time stamp: //')
  TSA_POLICY=$(echo "$TSA_TEXT" | grep 'Policy OID:'   | sed 's/.*Policy OID: //')
  TSA_SERIAL=$(echo "$TSA_TEXT" | grep 'Serial number:'| sed 's/.*Serial number: //')
  TSA_NAME=$(openssl ts -reply -in "$TMPDIR/tsa.tsr" -text 2>/dev/null \
    | grep -A1 'TSA:' | tail -1 | sed 's/^[[:space:]]*//' || echo "")

  echo ""
  echo "rfc 3161 timestamp"
  echo "  time      : $TSA_TIME"
  [ -n "$TSA_NAME" ]   && echo "  tsa       : $TSA_NAME"
  [ -n "$TSA_POLICY" ] && echo "  policy    : $TSA_POLICY"
  [ -n "$TSA_SERIAL" ] && echo "  serial    : $TSA_SERIAL"
fi
