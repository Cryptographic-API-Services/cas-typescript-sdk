import { expect, test } from "@playwright/test";
import { ChaCha20Poly1305Wrapper } from "../src-ts/symmetric/chacha20poly1305-wrapper";
import { areEqual } from "./helpers/array";

test.describe("ChaCha20-Poly1305 Tests", () => {
  test("encrypt and decrypt equals", () => {
    const chacha = new ChaCha20Poly1305Wrapper();
    const key = chacha.generateKey();
    const nonce = chacha.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = chacha.encrypt(key, nonce, plaintext);
    const decrypted = chacha.decrypt(key, nonce, ciphertext);
    expect(areEqual(decrypted, plaintext)).toBe(true);
  });

  test("decrypt with wrong key throws", () => {
    const chacha = new ChaCha20Poly1305Wrapper();
    const key = chacha.generateKey();
    const nonce = chacha.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = chacha.encrypt(key, nonce, plaintext);
    const wrongKey = chacha.generateKey();
    expect(() => chacha.decrypt(wrongKey, nonce, ciphertext)).toThrow();
  });
});
