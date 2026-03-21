# Paraph Attestations

Public transparency log for [Paraph](https://paraph.cc) — a timestamp attestation service.

Each attestation is a signed record proving that a specific set of bytes existed at a specific moment in time.

## How it works

When you submit data to Paraph, the service:

1. Computes `SHA-256(data)`
2. Builds a 40-byte signed payload: `timestamp (8 bytes, uint64 big-endian) || sha256 (32 bytes)`
3. Signs the payload with Ed25519 using the active service key
4. Commits the attestation record to this repository as a permanent public record

The original data is never stored — only its SHA-256 hash.

## Attestation records

Records are stored at:

```
attestations/{sig[0..1]}/{sig[2..3]}/{sig-128-hex}.json
```

The filename is the Ed25519 signature encoded as 128 lowercase hex characters.
Given only a signature you can derive the full path and retrieve the record.

Each record contains:

```json
{
  "key_id": "paraph-2026-01",
  "timestamp": 1742515200000,
  "sha256": "hex-encoded sha256 of the attested data",
  "signature": "base64url Ed25519 signature",
  "url": "https://github.com/paraph-cc/attestations/blob/main/attestations/ab/cd/{128-hex}.json"
}
```

If the attestation was created by the server fetching a URL, a `source_url` field is also present.

## Verifying an attestation

Two verification files are provided:

- `verify-lib.js` — pure Web Crypto, importable in a browser or Node.js 18+
- `verify-cli.js` — command line wrapper, requires Node.js 18+

**Command line:**

```sh
node verify-cli.js <record.json> <public-key.jwk> [data-file]
```

- `record.json` — the attestation JSON (from the API response or this repo)
- `public-key.jwk` — the public key from the `keys/` directory matching the record's `key_id`
- `data-file` — optional: your original data file, confirms its SHA-256 matches the record

Exit code 0 = valid, 1 = invalid.

**Shell (OpenSSL — no Node.js required):**

```sh
./verify.sh <record.json> <public-key.jwk> [data-file]
```

Requires: `openssl` 3.0+, `jq`, `python3`. All standard on Linux and macOS.

**Browser / ES module:**

```js
import { verify, checkHash } from './verify-lib.js';

const record = await fetch('attestations/2026/03/21/{id}.json').then((r) => r.json());
const key = await fetch('keys/paraph-2026-01.jwk').then((r) => r.json());

const valid = await verify(record, key);
```

## Public keys

Keys are in the `keys/` directory, one file per key ID:

```
keys/paraph-2026-01.jwk
```

Keys are never deleted — retired keys remain so old attestations can always be verified.

## What this proves

An attestation is a **self-attested timestamp** signed by the Paraph service. It proves:

- The Paraph service saw data with this SHA-256
- At the time indicated by the timestamp field
- The record has not been tampered with (signature would break)

It does **not** provide a trusted third-party timestamp (RFC 3161). The timestamp is set by the Paraph service clock at the moment of signing.
