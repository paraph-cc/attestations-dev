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
  "signature": "128-char lowercase hex Ed25519 signature",
  "tsr": "base64-encoded RFC 3161 TimeStampResponse from the TSA",
  "url": "https://github.com/paraph-cc/attestations/blob/main/attestations/ab/cd/{128-hex}.json"
}
```

If the attestation was created by the server fetching a URL, a `source_url` field is also present.

## Verifying an attestation

Three verification files are provided in `src/`:

- `src/verify-lib.js` — pure Web Crypto, importable in a browser or Node.js 18+
- `src/verify-cli.js` — command line wrapper, requires Node.js 18+
- `src/verify.sh` — shell wrapper using openssl, jq, python3, curl

Pass the signature and your original file — the verifier fetches the attestation record and public key from GitHub automatically:

```sh
./src/verify.sh <signature> <data-file>
node src/verify-cli.js <signature> <data-file>
```

Data can also be piped in:

```sh
cat broken-window.jpg | ./src/verify.sh <signature>
```

**With local record and key files (no network required):**

```sh
./src/verify.sh <record.json> <public-key.jwk> <data-file>
node src/verify-cli.js <record.json> <public-key.jwk> <data-file>
```

`src/verify.sh` requires: `openssl` 3.0+, `jq`, `python3`, `curl`. All standard on Linux and macOS.

Exit code 0 = valid, 1 = invalid.

Set `PARAPH_REPO=<name>` to verify against a different GitHub repo.

**Browser / ES module:**

```js
import { fetchAndVerify } from './src/verify-lib.js';

const { valid, dataMatch } = await fetchAndVerify(signature, { data: fileBytes });
// valid     — signature checks out
// dataMatch — your file's sha256 matches the record
```

## Public keys

Keys are in the `keys/` directory, one file per key ID:

```
keys/paraph-2026-01.jwk
```

Keys are never deleted — retired keys remain so old attestations can always be verified.

## What this proves

Each attestation record contains two independent timestamps:

**Ed25519 signature** — signed by the Paraph service key over `timestamp || sha256(data)`. Proves the Paraph service saw this data at this moment. Verifiable with the public key in `keys/`.

**RFC 3161 TSA token** (`tsr` field) — an independent timestamp from a trusted third-party TSA, covering `sha256(data)`. Verifiable with standard tools (`openssl ts -verify`) against the TSA's certificate chain, with no dependency on Paraph at all.

Together they mean: even if you distrust Paraph, the TSA independently witnessed the same data hash at a time consistent with the Ed25519 timestamp.

For full RFC 3161 chain verification you need the TSA's root certificate in your trust store.

**Sectigo** (`http://timestamp.sectigo.com`) — root is in all standard system CA bundles.
No extra configuration needed; chain verification works out of the box.

**FreeTSA** (`https://freetsa.org/tsr`) — a free community service whose root is _not_
in the standard system CA bundle. Download their root cert and pass it via `TSA_CA_FILE`:

```sh
curl -O https://www.freetsa.org/files/cacert.pem
TSA_CA_FILE=cacert.pem ./src/verify.sh <signature> <data-file>
TSA_CA_FILE=cacert.pem node src/verify-cli.js <signature> <data-file>
```

If you use FreeTSA, consider donating at [freetsa.org](https://www.freetsa.org) —
it is run as a free community service.

The TSA used for any given attestation is identified by the certificate embedded in the
`tsr` field itself — you do not need to know the TSA URL in advance. Use `src/inspect-cli.js`
or `src/inspect.sh` to see which TSA signed a record.
