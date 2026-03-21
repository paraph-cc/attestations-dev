#!/usr/bin/env node
/**
 * Paraph Attestation Verifier — CLI
 *
 * Usage:
 *   node verify-cli.js <signature>                        — fetch record and key from GitHub
 *   node verify-cli.js <record.json> <public-key.jwk> [data-file]
 *
 *   signature       : base64url signature from an attestation record
 *   record.json     : attestation JSON from POST /attest or the attestations repo
 *   public-key.jwk  : public key from the attestations repo keys/ directory
 *   data-file       : (optional) original data — confirms its sha256 matches the record
 *
 * Environment:
 *   PARAPH_REPO     : override the GitHub repo name (default: attestations)
 *
 * Exit codes:
 *   0  valid
 *   1  invalid or error
 */

import { readFileSync } from 'node:fs';
import { fetchAndVerify, verify, checkHash } from './verify-lib.js';

const args = process.argv.slice(2);

let record, publicKeyJwk, dataFile;

if (args.length === 1) {
  // Single signature argument — fetch record and key from GitHub
  const signature = args[0];
  const repo = process.env.PARAPH_REPO;

  process.stderr.write('fetching attestation...\n');
  let result;
  try {
    result = await fetchAndVerify(signature, repo ? { repo } : {});
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exit(1);
  }

  printResult(result.valid, result.record);
} else {
  // File-based: record.json + public-key.jwk [data-file]
  const [recordFile, pubKeyFile, dataFilePath] = args;

  if (!recordFile || !pubKeyFile) {
    console.error('Usage: node verify-cli.js <signature>');
    console.error('       node verify-cli.js <record.json> <public-key.jwk> [data-file]');
    process.exit(1);
  }

  try {
    record = JSON.parse(readFileSync(recordFile, 'utf8'));
    publicKeyJwk = JSON.parse(readFileSync(pubKeyFile, 'utf8'));
  } catch (err) {
    console.error(`error reading files: ${err.message}`);
    process.exit(1);
  }

  if (dataFilePath) {
    const data = readFileSync(dataFilePath);
    const match = await checkHash(record, data);
    if (!match) {
      console.error('INVALID — data hash mismatch');
      console.error(`  record.sha256 : ${record.sha256}`);
      process.exit(1);
    }
    console.log('ok  data hash matches record');
  }

  let valid;
  try {
    valid = await verify(record, publicKeyJwk);
  } catch (err) {
    console.error(`error during verification: ${err.message}`);
    process.exit(1);
  }

  printResult(valid, record);
}

function printResult(valid, record) {
  if (valid) {
    const date = new Date(record.timestamp).toISOString();
    console.log('ok  signature valid');
    console.log(`    key_id    : ${record.key_id}`);
    console.log(`    timestamp : ${record.timestamp}  (${date})`);
    console.log(`    sha256    : ${record.sha256}`);
    process.exit(0);
  } else {
    console.error('INVALID — signature does not verify');
    process.exit(1);
  }
}
