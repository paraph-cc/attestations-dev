/**
 * Paraph verification library.
 * Works in any environment with Web Crypto and fetch (browser, Node 18+, CF Workers).
 * No imports, no dependencies.
 */

const GITHUB_RAW = 'https://raw.githubusercontent.com/paraph-cc';

/**
 * Fetch an attestation record and its public key from GitHub, then verify.
 *
 * @param {string} signature - base64url signature from an attestation record
 * @param {object} [options]
 * @param {string} [options.repo='attestations']  - GitHub repo name override
 * @param {object} [options.record]               - supply record directly (skip fetch)
 * @param {object} [options.publicKeyJwk]         - supply public key directly (skip fetch)
 * @returns {Promise<{ valid: boolean, record: object, publicKeyJwk: object }>}
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
  return { valid, record, publicKeyJwk };
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

  return crypto.subtle.verify('Ed25519', publicKey, fromBase64url(record.signature), payload);
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

/** Derive the GitHub repo path from a base64url signature. */
function sigToPath(signature) {
  const hex = toHex(fromBase64url(signature));
  return `attestations/${hex.slice(0, 2)}/${hex.slice(2, 4)}/${hex}.json`;
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
