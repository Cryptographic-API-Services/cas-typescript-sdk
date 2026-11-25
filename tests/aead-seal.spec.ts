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

interface SealCipher {
  name: string;
  nonceLength: number;
  key: () => Bytes;
  seal: (key: Bytes, plaintext: Bytes, aad?: Bytes) => Bytes;
  open: (key: Bytes, sealed: Bytes, aad?: Bytes) => Bytes;
  decrypt: (key: Bytes, nonce: Bytes, ciphertext: Bytes) => Bytes;
}

const TAG_LENGTH = 16;
const aes = new AESWrapper();
const siv = new AESGCMSIVWrapper();
const chacha = new ChaCha20Poly1305Wrapper();
const ascon = new AsconWrapper();

const ciphers: SealCipher[] = [
  {
    name: "AES-128-GCM",
    nonceLength: 12,
    key: () => aes.aes128Key(),
    seal: (k, p, a) => aes.aes128Seal(k, p, a),
    open: (k, s, a) => aes.aes128Open(k, s, a),
    decrypt: (k, n, c) => aes.aes128Decrypt(k, n, c),
  },
  {
    name: "AES-256-GCM",
    nonceLength: 12,
    key: () => aes.aes256Key(),
    seal: (k, p, a) => aes.aes256Seal(k, p, a),
    open: (k, s, a) => aes.aes256Open(k, s, a),
    decrypt: (k, n, c) => aes.aes256Decrypt(k, n, c),
  },
  {
    name: "AES-128-GCM-SIV",
    nonceLength: 12,
    key: () => siv.aes128Key(),
    seal: (k, p, a) => siv.aes128Seal(k, p, a),
    open: (k, s, a) => siv.aes128Open(k, s, a),
    decrypt: (k, n, c) => siv.aes128Decrypt(k, n, c),
  },
  {
    name: "AES-256-GCM-SIV",
    nonceLength: 12,
    key: () => siv.aes256Key(),
    seal: (k, p, a) => siv.aes256Seal(k, p, a),
    open: (k, s, a) => siv.aes256Open(k, s, a),
    decrypt: (k, n, c) => siv.aes256Decrypt(k, n, c),
  },
  {
    name: "ChaCha20-Poly1305",
    nonceLength: 12,
    key: () => chacha.generateKey(),
    seal: (k, p, a) => chacha.seal(k, p, a),
    open: (k, s, a) => chacha.open(k, s, a),
    decrypt: (k, n, c) => chacha.decrypt(k, n, c),
  },
  {
    name: "Ascon-AEAD128",
    nonceLength: 16,
    key: () => ascon.ascon128Key(),
    seal: (k, p, a) => ascon.ascon128Seal(k, p, a),
    open: (k, s, a) => ascon.ascon128Open(k, s, a),
    decrypt: (k, n, c) => ascon.ascon128Decrypt(k, n, c),
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
  test.describe(`${cipher.name} seal / open`, () => {
    const plaintext = toBytes("WelcomeHome");
    const aad = toBytes("message-id: 42");

    test("round trip without AAD", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, plaintext);
      expect(sealed.length).toBe(cipher.nonceLength + plaintext.length + TAG_LENGTH);
      expect(areEqual(cipher.open(key, sealed), plaintext)).toBe(true);
      expect(areEqual(cipher.open(key, sealed, []), plaintext)).toBe(true);
    });

    test("round trip with AAD", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, plaintext, aad);
      expect(areEqual(cipher.open(key, sealed, aad), plaintext)).toBe(true);
    });

    test("round trip of an empty plaintext", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, []);
      expect(sealed.length).toBe(cipher.nonceLength + TAG_LENGTH);
      expect(cipher.open(key, sealed)).toEqual([]);
    });

    test("tampered nonce, ciphertext or tag throws CAS_DECRYPTION_FAILED", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, plaintext, aad);
      for (const index of [0, cipher.nonceLength, sealed.length - 1]) {
        const tampered = [...sealed];
        tampered[index] ^= 0x01;
        expectCode(() => cipher.open(key, tampered, aad), CasErrorCode.DecryptionFailed);
      }
    });

    test("wrong or missing AAD throws CAS_DECRYPTION_FAILED", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, plaintext, aad);
      expectCode(() => cipher.open(key, sealed, toBytes("message-id: 43")), CasErrorCode.DecryptionFailed);
      expectCode(() => cipher.open(key, sealed), CasErrorCode.DecryptionFailed);
      expectCode(() => cipher.open(key, cipher.seal(key, plaintext), aad), CasErrorCode.DecryptionFailed);
    });

    test("wrong key throws CAS_DECRYPTION_FAILED", () => {
      const sealed = cipher.seal(cipher.key(), plaintext);
      expectCode(() => cipher.open(cipher.key(), sealed), CasErrorCode.DecryptionFailed);
    });

    test("wrong key length throws CAS_INVALID_KEY", () => {
      const key = cipher.key();
      expectCode(() => cipher.seal(key.slice(1), plaintext), CasErrorCode.InvalidKey);
      expectCode(() => cipher.open(key.slice(1), cipher.seal(key, plaintext)), CasErrorCode.InvalidKey);
    });

    test("two seals of the same plaintext differ, nonce prefix included", () => {
      const key = cipher.key();
      const first = cipher.seal(key, plaintext);
      const second = cipher.seal(key, plaintext);
      expect(areEqual(first, second)).toBe(false);
      expect(areEqual(first.slice(0, cipher.nonceLength), second.slice(0, cipher.nonceLength))).toBe(false);
    });

    test("a blob shorter than nonce + tag throws CAS_INVALID_INPUT", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, []);
      expectCode(() => cipher.open(key, sealed.slice(0, -1)), CasErrorCode.InvalidInput);
      expectCode(() => cipher.open(key, []), CasErrorCode.InvalidInput);
    });

    test("sealed blob is nonce || ciphertext || tag, readable by decrypt", () => {
      const key = cipher.key();
      const sealed = cipher.seal(key, plaintext);
      const nonce = sealed.slice(0, cipher.nonceLength);
      const ciphertext = sealed.slice(cipher.nonceLength);
      expect(areEqual(cipher.decrypt(key, nonce, ciphertext), plaintext)).toBe(true);
    });
  });
}
