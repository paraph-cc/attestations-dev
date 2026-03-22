#!/usr/bin/env node
/**
 * Paraph Attestation Verifier — CLI
 *
 * Usage:
 *   node verify-cli.js <signature> <data-file>         — fetch record and key from GitHub
 *   node verify-cli.js <record.json> <public-key.jwk> <data-file>
 *
 *   Data can also be piped via stdin instead of passing a data-file.
 *
 *   signature       : base64url signature from an attestation record
 *   record.json     : attestation JSON from POST /attest or the attestations repo
 *   public-key.jwk  : public key from the attestations repo keys/ directory
 *   data-file       : your original data — verifies its sha256 matches the record
 *
 * Environment:
 *   PARAPH_REPO     : override the GitHub repo name (default: attestations)
 *   NODE_ENV=dev|staging|prod : load .env.{NODE_ENV} from the current directory
 *   TSA_CA_FILE     : PEM file for RFC 3161 chain verification (optional)
 *
 * Exit codes:
 *   0  valid
 *   1  invalid or error
 */

import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fetchAndVerify, verify, checkHash } from './verify-lib.js';

const NODE_ENV = process.env.NODE_ENV;
if (NODE_ENV === 'dev' || NODE_ENV === 'staging' || NODE_ENV === 'prod') {
  try {
    const env = readFileSync(`.env.${NODE_ENV}`, 'utf8');
    for (const line of env.split('\n')) {
      const match = line.match(/^([^#=\s][^=]*)=(.*)$/);
      if (match) process.env[match[1].trim()] ??= match[2].trim();
    }
  } catch {
    // no env file
  }
}

const args = process.argv.slice(2);

if (args.length === 0) {
  console.error('Usage: node verify-cli.js <signature> <data-file>');
  console.error('       node verify-cli.js <record.json> <public-key.jwk> <data-file>');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Resolve record, publicKeyJwk, data — either from GitHub or local files.
// ---------------------------------------------------------------------------
let record, publicKeyJwk, data;

if (!existsSync(args[0])) {
  // Signature mode — fetch record and key from GitHub
  const [signature, dataFile] = args;
  const repo = process.env.PARAPH_REPO ?? process.env.GITHUB_REPO;

  process.stderr.write('fetching attestation...\n');
  try {
    ({ record, publicKeyJwk } = await fetchAndVerify(signature, repo ? { repo } : {}));
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exit(1);
  }

  if (!dataFile && process.stdin.isTTY) {
    console.error('error: data file required — pass your original file or pipe it via stdin');
    console.error('  node verify-cli.js <signature> <data-file>');
    console.error('  cat <data-file> | node verify-cli.js <signature>');
    process.exit(1);
  }

  data = dataFile ? readFileSync(dataFile) : await readStdin();
} else {
  // File mode — record.json + public-key.jwk + data
  const [recordFile, pubKeyFile, dataFilePath] = args;

  if (!pubKeyFile) {
    console.error('Usage: node verify-cli.js <signature> <data-file>');
    console.error('       node verify-cli.js <record.json> <public-key.jwk> <data-file>');
    process.exit(1);
  }

  try {
    record = JSON.parse(readFileSync(recordFile, 'utf8'));
    publicKeyJwk = JSON.parse(readFileSync(pubKeyFile, 'utf8'));
  } catch (err) {
    console.error(`error reading files: ${err.message}`);
    process.exit(1);
  }

  if (!dataFilePath && process.stdin.isTTY) {
    console.error('error: data file required — pass your original file or pipe it via stdin');
    console.error('  node verify-cli.js <record.json> <public-key.jwk> <data-file>');
    console.error('  cat <data-file> | node verify-cli.js <record.json> <public-key.jwk>');
    process.exit(1);
  }

  data = dataFilePath ? readFileSync(dataFilePath) : await readStdin();
}

// ---------------------------------------------------------------------------
// 1. Verify data hash matches record.
// ---------------------------------------------------------------------------
if (!(await checkHash(record, data))) {
  console.error('INVALID — data hash mismatch');
  console.error(`  record.sha256 : ${record.sha256}`);
  process.exit(1);
}
console.log('ok  data matches record');

// ---------------------------------------------------------------------------
// 2. Verify RFC 3161 TSA timestamp if present.
// ---------------------------------------------------------------------------
if (record.tsr) {
  verifyTsa(record.tsr, data);
}

// ---------------------------------------------------------------------------
// 3. Verify Ed25519 signature.
// ---------------------------------------------------------------------------
let valid;
try {
  valid = await verify(record, publicKeyJwk);
} catch (err) {
  console.error(`error during verification: ${err.message}`);
  process.exit(1);
}

if (!valid) {
  console.error('INVALID — signature does not verify');
  process.exit(1);
}

const date = new Date(record.timestamp).toISOString();
console.log('ok  signature valid');
console.log(`    key_id    : ${record.key_id}`);
console.log(`    timestamp : ${record.timestamp}  (${date})`);
console.log(`    sha256    : ${record.sha256}`);
process.exit(0);

// ---------------------------------------------------------------------------

/**
 * Verify an RFC 3161 TSR against the data using openssl.
 * Tries the system CA store then TSA_CA_FILE env var.
 * Prints result; does not exit on chain failure (warn only).
 */
function verifyTsa(tsrBase64, data) {
  const tmp = mkdtempSync(join(tmpdir(), 'paraph-'));
  try {
    const tsrPath = join(tmp, 'tsa.tsr');
    const dataPath = join(tmp, 'data.bin');
    writeFileSync(tsrPath, Buffer.from(tsrBase64, 'base64'));
    writeFileSync(dataPath, data);

    // Extract timestamp from TSR regardless of chain result
    const info = spawnSync('openssl', ['ts', '-reply', '-in', tsrPath, '-text'], {
      encoding: 'utf8',
    });
    const timeMatch = info.stdout?.match(/Time stamp: (.+)/);
    const tsaTime = timeMatch ? timeMatch[1].trim() : 'unknown';

    // Find CA bundle
    let caFile = process.env.TSA_CA_FILE ?? null;
    if (!caFile) {
      for (const f of ['/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem']) {
        if (existsSync(f)) {
          caFile = f;
          break;
        }
      }
    }

    const verifyArgs = ['ts', '-verify', '-in', tsrPath, '-data', dataPath];
    if (caFile) verifyArgs.push('-CAfile', caFile);

    const result = spawnSync('openssl', verifyArgs, { encoding: 'utf8' });

    if (result.status === 0) {
      console.log(`ok  RFC 3161 timestamp verified  (${tsaTime})`);
    } else {
      process.stderr.write('warn RFC 3161 timestamp present but chain not verified\n');
      process.stderr.write(`     timestamp : ${tsaTime}\n`);
      process.stderr.write('     set TSA_CA_FILE=/path/to/tsa-root.pem for full chain verification\n');
    }
  } finally {
    rmSync(tmp, { recursive: true });
  }
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}
