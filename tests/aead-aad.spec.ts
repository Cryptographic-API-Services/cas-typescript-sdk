import { expect, test } from "@playwright/test";
import {
  AESGCMSIVWrapper,
  AESWrapper,
  AsconWrapper,
  CasErrorCode,
  ChaCha20Poly1305Wrapper,
  isCasError,
} from "../src-ts/index";
import { areEqual } from "./helpers/array";

type Bytes = Array<number>;

interface AadCipher {
  name: string;
  key: () => Bytes;
  nonce: () => Bytes;
  encrypt: (key: Bytes, nonce: Bytes, plaintext: Bytes) => Bytes;
  decrypt: (key: Bytes, nonce: Bytes, ciphertext: Bytes) => Bytes;
  encryptWithAad: (key: Bytes, nonce: Bytes, plaintext: Bytes, aad: Bytes) => Bytes;
  decryptWithAad: (key: Bytes, nonce: Bytes, ciphertext: Bytes, aad: Bytes) => Bytes;
  open: (key: Bytes, sealed: Bytes, aad?: Bytes) => Bytes;
}

const aes = new AESWrapper();
const siv = new AESGCMSIVWrapper();
const chacha = new ChaCha20Poly1305Wrapper();
const ascon = new AsconWrapper();

const ciphers: AadCipher[] = [
  {
    name: "AES-128-GCM",
    key: () => aes.aes128Key(),
    nonce: () => aes.generateAESNonce(),
    encrypt: (k, n, p) => aes.aes128Encrypt(k, n, p),
    decrypt: (k, n, c) => aes.aes128Decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => aes.aes128EncryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => aes.aes128DecryptWithAad(k, n, c, a),
    open: (k, s, a) => aes.aes128Open(k, s, a),
  },
  {
    name: "AES-256-GCM",
    key: () => aes.aes256Key(),
    nonce: () => aes.generateAESNonce(),
    encrypt: (k, n, p) => aes.aes256Encrypt(k, n, p),
    decrypt: (k, n, c) => aes.aes256Decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => aes.aes256EncryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => aes.aes256DecryptWithAad(k, n, c, a),
    open: (k, s, a) => aes.aes256Open(k, s, a),
  },
  {
    name: "AES-128-GCM-SIV",
    key: () => siv.aes128Key(),
    nonce: () => siv.generateNonce(),
    encrypt: (k, n, p) => siv.aes128Encrypt(k, n, p),
    decrypt: (k, n, c) => siv.aes128Decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => siv.aes128EncryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => siv.aes128DecryptWithAad(k, n, c, a),
    open: (k, s, a) => siv.aes128Open(k, s, a),
  },
  {
    name: "AES-256-GCM-SIV",
    key: () => siv.aes256Key(),
    nonce: () => siv.generateNonce(),
    encrypt: (k, n, p) => siv.aes256Encrypt(k, n, p),
    decrypt: (k, n, c) => siv.aes256Decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => siv.aes256EncryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => siv.aes256DecryptWithAad(k, n, c, a),
    open: (k, s, a) => siv.aes256Open(k, s, a),
  },
  {
    name: "ChaCha20-Poly1305",
    key: () => chacha.generateKey(),
    nonce: () => chacha.generateNonce(),
    encrypt: (k, n, p) => chacha.encrypt(k, n, p),
    decrypt: (k, n, c) => chacha.decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => chacha.encryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => chacha.decryptWithAad(k, n, c, a),
    open: (k, s, a) => chacha.open(k, s, a),
  },
  {
    name: "Ascon-AEAD128",
    key: () => ascon.ascon128Key(),
    nonce: () => ascon.ascon128Nonce(),
    encrypt: (k, n, p) => ascon.ascon128Encrypt(k, n, p),
    decrypt: (k, n, c) => ascon.ascon128Decrypt(k, n, c),
    encryptWithAad: (k, n, p, a) => ascon.ascon128EncryptWithAad(k, n, p, a),
    decryptWithAad: (k, n, c, a) => ascon.ascon128DecryptWithAad(k, n, c, a),
    open: (k, s, a) => ascon.ascon128Open(k, s, a),
  },
];

const toBytes = (text: string): Bytes => Array.from(new TextEncoder().encode(text));

function expectCode(fn: () => unknown, code: CasErrorCode): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect((caught as { code?: unknown } | undefined)?.code).toBe(code);
  expect(isCasError(caught, code)).toBe(true);
}

for (const cipher of ciphers) {
  test.describe(`${cipher.name} encryptWithAad / decryptWithAad`, () => {
    const plaintext = toBytes("WelcomeHome");
    const aad = toBytes("record-id: 7");

    test("round trip with AAD", () => {
      const key = cipher.key();
      const nonce = cipher.nonce();
      const ciphertext = cipher.encryptWithAad(key, nonce, plaintext, aad);
      expect(areEqual(cipher.decryptWithAad(key, nonce, ciphertext, aad), plaintext)).toBe(true);
    });

    test("wrong or missing AAD throws CAS_DECRYPTION_FAILED", () => {
      const key = cipher.key();
      const nonce = cipher.nonce();
      const ciphertext = cipher.encryptWithAad(key, nonce, plaintext, aad);
      expectCode(() => cipher.decryptWithAad(key, nonce, ciphertext, toBytes("record-id: 8")), CasErrorCode.DecryptionFailed);
      expectCode(() => cipher.decryptWithAad(key, nonce, ciphertext, []), CasErrorCode.DecryptionFailed);
      expectCode(() => cipher.decrypt(key, nonce, ciphertext), CasErrorCode.DecryptionFailed);
    });

    test("empty AAD gives the same output as the API without AAD", () => {
      const key = cipher.key();
      const nonce = cipher.nonce();
      const withEmptyAad = cipher.encryptWithAad(key, nonce, plaintext, []);
      expect(areEqual(withEmptyAad, cipher.encrypt(key, nonce, plaintext))).toBe(true);
      expect(areEqual(cipher.decrypt(key, nonce, withEmptyAad), plaintext)).toBe(true);
      expect(areEqual(cipher.decryptWithAad(key, nonce, cipher.encrypt(key, nonce, plaintext), []), plaintext)).toBe(true);
    });

    test("nonce || encryptWithAad output opens with the same AAD", () => {
      const key = cipher.key();
      const nonce = cipher.nonce();
      const sealed = [...nonce, ...cipher.encryptWithAad(key, nonce, plaintext, aad)];
      expect(areEqual(cipher.open(key, sealed, aad), plaintext)).toBe(true);
    });

    test("wrong key or nonce length throws CAS_INVALID_KEY / CAS_INVALID_NONCE", () => {
      const key = cipher.key();
      const nonce = cipher.nonce();
      expectCode(() => cipher.encryptWithAad(key.slice(1), nonce, plaintext, aad), CasErrorCode.InvalidKey);
      expectCode(() => cipher.encryptWithAad(key, nonce.slice(1), plaintext, aad), CasErrorCode.InvalidNonce);
      const ciphertext = cipher.encryptWithAad(key, nonce, plaintext, aad);
      expectCode(() => cipher.decryptWithAad(key, nonce.slice(1), ciphertext, aad), CasErrorCode.InvalidNonce);
    });
  });
}
