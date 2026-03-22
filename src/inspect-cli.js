#!/usr/bin/env node
/**
 * Paraph Attestation Inspector — CLI
 *
 * Prints human-readable details about an attestation record,
 * including TSA certificate information extracted via openssl.
 *
 * Usage:
 *   node inspect-cli.js <signature>      — fetch record from GitHub
 *   node inspect-cli.js <record.json>    — use local record file
 *
 * Environment:
 *   PARAPH_REPO     : override the GitHub repo name (default: attestations)
 *   NODE_ENV=dev|staging|prod : load .env.{NODE_ENV} from the current directory
 */

import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { inspect } from './verify-lib.js';

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
  console.error('Usage: node inspect-cli.js <signature>');
  console.error('       node inspect-cli.js <record.json>');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Resolve the record.
// ---------------------------------------------------------------------------
let record;

if (!existsSync(args[0])) {
  const signature = args[0];
  const repo = process.env.PARAPH_REPO ?? process.env.GITHUB_REPO;
  const base = `https://raw.githubusercontent.com/paraph-cc/${repo ?? 'attestations'}/main`;
  const sig = signature;
  const path = `attestations/${sig.slice(0, 2)}/${sig.slice(2, 4)}/${sig}.json`;

  process.stderr.write('fetching attestation...\n');
  const res = await fetch(`${base}/${path}`);
  if (!res.ok) {
    console.error(`error: attestation not found (${res.status}): ${path}`);
    process.exit(1);
  }
  record = await res.json();
} else {
  try {
    record = JSON.parse(readFileSync(args[0], 'utf8'));
  } catch (err) {
    console.error(`error reading file: ${err.message}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Print record summary via verify-lib inspect().
// ---------------------------------------------------------------------------
const info = inspect(record);

console.log('attestation');
console.log(`  key_id    : ${info.key_id}`);
console.log(`  timestamp : ${info.timestamp}  (${info.timestamp_iso})`);
console.log(`  sha256    : ${info.sha256}`);
console.log(`  signature : ${info.signature}`);
if (info.source_url) console.log(`  source    : ${info.source_url}`);
if (info.url) console.log(`  url       : ${info.url}`);

// ---------------------------------------------------------------------------
// Print detailed TSA info via openssl if tsr is present.
// ---------------------------------------------------------------------------
if (record.tsr) {
  const tmp = mkdtempSync(join(tmpdir(), 'paraph-'));
  try {
    const tsrPath = join(tmp, 'tsa.tsr');
    writeFileSync(tsrPath, Buffer.from(record.tsr, 'base64'));

    const r = spawnSync('openssl', ['ts', '-reply', '-in', tsrPath, '-text'], {
      encoding: 'utf8',
    });
    const text = r.stdout ?? '';

    const get = (label) => {
      const m = text.match(new RegExp(`${label}:\\s*(.+)`));
      return m ? m[1].trim() : null;
    };

    const tsaMatch = text.match(/TSA:\s*(?:DirName:)?(.+)/);
    const tsaName = tsaMatch ? tsaMatch[1].trim() : null;

    console.log('');
    console.log('rfc 3161 timestamp');
    if (info.tsa?.timestamp) console.log(`  time      : ${info.tsa.timestamp}`);
    if (tsaName) console.log(`  tsa       : ${tsaName}`);
    const policy = get('Policy OID');
    if (policy) console.log(`  policy    : ${policy}`);
    const serial = get('Serial number');
    if (serial) console.log(`  serial    : ${serial}`);
  } finally {
    rmSync(tmp, { recursive: true });
  }
}
