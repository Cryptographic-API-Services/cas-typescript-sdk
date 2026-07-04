import { expect, test } from "@playwright/test";
import { AESGCMSIVWrapper } from "../src-ts/symmetric/aes-gcm-siv-wrapper";
import { areEqual } from "./helpers/array";

test.describe("AES-GCM-SIV Tests", () => {
  test("aes 128 encrypt and decrypt equals", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes128Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes128Encrypt(key, nonce, plaintext);
    const decrypted = aes.aes128Decrypt(key, nonce, ciphertext);
    expect(areEqual(decrypted, plaintext)).toBe(true);
  });

  test("aes 256 encrypt and decrypt equals", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    const decrypted = aes.aes256Decrypt(key, nonce, ciphertext);
    expect(areEqual(decrypted, plaintext)).toBe(true);
  });

  test("decrypt with wrong key throws", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    const wrongKey = aes.aes256Key();
    expect(() => aes.aes256Decrypt(wrongKey, nonce, ciphertext)).toThrow();
  });

  test("key from bytes validates length", () => {
    const aes = new AESGCMSIVWrapper();
    expect(() => aes.aes128KeyFromBytes([1, 2, 3])).toThrow();
    expect(() => aes.aes256KeyFromBytes([1, 2, 3])).toThrow();
    expect(aes.aes128KeyFromBytes(new Array(16).fill(0)).length).toBe(16);
    expect(aes.aes256KeyFromBytes(new Array(32).fill(0)).length).toBe(32);
  });
});
