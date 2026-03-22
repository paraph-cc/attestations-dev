/**
 * Paraph verification library.
 * Works in any environment with Web Crypto and fetch (browser, Node 18+, CF Workers).
 * No imports, no dependencies.
 */

const GITHUB_RAW = 'https://raw.githubusercontent.com/paraph-cc';

/**
 * Return a structured, human-readable summary of an attestation record.
 * If the record contains a TSR, extracts the TSA timestamp from the DER.
 * @param {object} record
 * @returns {{ key_id, timestamp, timestamp_iso, sha256, signature, tsa?, source_url?, url? }}
 */
export function inspect(record) {
  const result = {
    key_id: record.key_id,
    timestamp: record.timestamp,
    timestamp_iso: new Date(record.timestamp).toISOString(),
    sha256: record.sha256,
    signature: record.signature,
  };

  if (record.source_url) result.source_url = record.source_url;
  if (record.url) result.url = record.url;

  if (record.tsr) {
    const tsaTime = parseTsrGenTime(record.tsr);
    result.tsa = { timestamp: tsaTime ? tsaTime.toISOString() : null };
  }

  return result;
}

/**
 * Extract the genTime from an RFC 3161 TSR by scanning for the first
 * GeneralizedTime (tag 0x18) in the DER — which is TSTInfo.genTime,
 * appearing before any certificate validity dates in the structure.
 * @param {string} tsrBase64
 * @returns {Date|null}
 */
function parseTsrGenTime(tsrBase64) {
  const b64 = tsrBase64.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const buf = Uint8Array.from(bin, (c) => c.charCodeAt(0));

  for (let i = 0; i < buf.length - 16; i++) {
    if (buf[i] === 0x18) {
      const len = buf[i + 1];
      if (len >= 13 && len <= 24) {
        const str = String.fromCharCode(...buf.slice(i + 2, i + 2 + len));
        // GeneralizedTime: YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS.sssZ
        if (/^\d{14}(\.\d+)?Z$/.test(str)) {
          return new Date(
            `${str.slice(0, 4)}-${str.slice(4, 6)}-${str.slice(6, 8)}` +
              `T${str.slice(8, 10)}:${str.slice(10, 12)}:${str.slice(12, 14)}Z`,
          );
        }
      }
    }
  }
  return null;
}

/**
 * Fetch an attestation record and its public key from GitHub, then verify.
 *
 * @param {string} signature - base64url signature from an attestation record
 * @param {object} [options]
 * @param {string} [options.repo='attestations']        - GitHub repo name override
 * @param {object} [options.record]                     - supply record directly (skip fetch)
 * @param {object} [options.publicKeyJwk]               - supply public key directly (skip fetch)
 * @param {Uint8Array|ArrayBuffer} [options.data]       - original data to hash-check against record
 * @returns {Promise<{ valid: boolean, dataMatch: boolean|null, record: object, publicKeyJwk: object }>}
 */
export async function fetchAndVerify(signature, options = {}) {
  const repo = options.repo ?? 'attestations';
  const base = `${GITHUB_RAW}/${repo}/main`;

  let record = options.record ?? null;
  if (!record) {
    const path = sigToPath(signature);
    const res = await fetch(`${base}/${path}`);
    if (!res.ok) throw new Error(`attestation not found (${res.status}): ${path}`);
    record = await res.json();
  }

  let publicKeyJwk = options.publicKeyJwk ?? null;
  if (!publicKeyJwk) {
    const res = await fetch(`${base}/keys/${record.key_id}.jwk`);
    if (!res.ok) throw new Error(`public key not found (${res.status}): keys/${record.key_id}.jwk`);
    publicKeyJwk = await res.json();
  }

  const valid = await verify(record, publicKeyJwk);
  const dataMatch = options.data != null ? await checkHash(record, options.data) : null;
  return { valid, dataMatch, record, publicKeyJwk };
}

/**
 * Verify a Paraph attestation record against a public key JWK.
 * @param {{ timestamp: number, sha256: string, signature: string }} record
 * @param {object} publicKeyJwk - Ed25519 public key in JWK format
 * @returns {Promise<boolean>}
 */
export async function verify(record, publicKeyJwk) {
  const publicKey = await crypto.subtle.importKey('jwk', publicKeyJwk, { name: 'Ed25519' }, false, ['verify']);

  const sha256Bytes = fromHex(record.sha256);

  // Signed payload: 8-byte big-endian uint64 timestamp || 32-byte sha256
  const payload = new Uint8Array(40);
  const view = new DataView(payload.buffer);
  view.setBigUint64(0, BigInt(record.timestamp), false);
  payload.set(sha256Bytes, 8);

  return crypto.subtle.verify('Ed25519', publicKey, fromHex(record.signature), payload);
}

/**
 * Compute SHA-256 of data and check it matches the sha256 field in the record.
 * @param {{ sha256: string }} record
 * @param {Uint8Array | ArrayBuffer} data - the original data that was attested
 * @returns {Promise<boolean>}
 */
export async function checkHash(record, data) {
  const hashBuf = await crypto.subtle.digest('SHA-256', data);
  return toHex(new Uint8Array(hashBuf)) === record.sha256;
}

/** Derive the GitHub repo path from a hex signature. */
function sigToPath(signature) {
  return `attestations/${signature.slice(0, 2)}/${signature.slice(2, 4)}/${signature}.json`;
}

/** @param {string} hex @returns {Uint8Array} */
function fromHex(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

/** @param {Uint8Array} bytes @returns {string} lowercase hex */
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** @param {string} b64url @returns {Uint8Array} */
function fromBase64url(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
