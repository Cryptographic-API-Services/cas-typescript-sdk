import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

import { run, bench, group, summary } from "mitata";

import { AESWrapper } from "../src-ts/symmetric";

// CAS AES is AES-GCM under the hood (96-bit / 12-byte nonce, 128- or 256-bit
// keys), so the apples-to-apples comparison is Node's OpenSSL-backed
// `aes-128-gcm` / `aes-256-gcm`. We measure CAS's Rust/RustCrypto path against
// it across a few representative payload sizes.
//
// CAS now takes/returns Uint8Array across the FFI boundary, and Node's Buffer
// *is* a Uint8Array, so both sides share the exact same byte buffers with no
// per-element boxing or conversion inside the measured loop.

const aes = new AESWrapper();

// Representative payloads: a small record, a typical message, and a 1 MiB blob
// to surface per-byte throughput rather than fixed call overhead.
const SIZES: Array<[label: string, bytes: number]> = [
  ["1 KiB", 1024],
  ["64 KiB", 64 * 1024],
  ["1 MiB", 1024 * 1024],
];

const payloads = SIZES.map(([label, bytes]) => ({
  label,
  buf: randomBytes(bytes), // Buffer === Uint8Array; consumed by both sides
}));

// --- Keys / nonces -----------------------------------------------------------
// CAS key/nonce helpers return Uint8Array; Node accepts those directly as key
// material, so both ciphers operate on identical bytes.
const key128 = aes.aes128Key();
const key256 = aes.aes256Key();
const nonce = aes.generateAESNonce();

function nodeGcmEncrypt(
  algo: "aes-128-gcm" | "aes-256-gcm",
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Buffer {
  const cipher = createCipheriv(algo, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // Append the auth tag so the output matches CAS's combined ciphertext||tag.
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

function nodeGcmDecrypt(
  algo: "aes-128-gcm" | "aes-256-gcm",
  key: Uint8Array,
  iv: Uint8Array,
  combined: Uint8Array,
): Buffer {
  const tag = combined.subarray(combined.length - 16);
  const ct = combined.subarray(0, combined.length - 16);
  const decipher = createDecipheriv(algo, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// Pre-compute ciphertexts so the decrypt benchmarks have valid input without
// encrypting inside the measured loop.
const ciphertexts = payloads.map(({ label, buf }) => ({
  label,
  cas128: aes.aes128Encrypt(key128, nonce, buf),
  cas256: aes.aes256Encrypt(key256, nonce, buf),
  node128: nodeGcmEncrypt("aes-128-gcm", key128, nonce, buf),
  node256: nodeGcmEncrypt("aes-256-gcm", key256, nonce, buf),
}));

// --- Encrypt -----------------------------------------------------------------
for (const { label, buf } of payloads) {
  group(`AES-128-GCM encrypt — ${label}`, () => {
    summary(() => {
      bench("CAS (cas-lib)", () => aes.aes128Encrypt(key128, nonce, buf));
      bench("Node crypto", () => nodeGcmEncrypt("aes-128-gcm", key128, nonce, buf));
    });
  });

  group(`AES-256-GCM encrypt — ${label}`, () => {
    summary(() => {
      bench("CAS (cas-lib)", () => aes.aes256Encrypt(key256, nonce, buf));
      bench("Node crypto", () => nodeGcmEncrypt("aes-256-gcm", key256, nonce, buf));
    });
  });
}

// --- Decrypt -----------------------------------------------------------------
for (const { label, cas128, cas256, node128, node256 } of ciphertexts) {
  group(`AES-128-GCM decrypt — ${label}`, () => {
    summary(() => {
      bench("CAS (cas-lib)", () => aes.aes128Decrypt(key128, nonce, cas128));
      bench("Node crypto", () => nodeGcmDecrypt("aes-128-gcm", key128, nonce, node128));
    });
  });

  group(`AES-256-GCM decrypt — ${label}`, () => {
    summary(() => {
      bench("CAS (cas-lib)", () => aes.aes256Decrypt(key256, nonce, cas256));
      bench("Node crypto", () => nodeGcmDecrypt("aes-256-gcm", key256, nonce, node256));
    });
  });
}

run();
