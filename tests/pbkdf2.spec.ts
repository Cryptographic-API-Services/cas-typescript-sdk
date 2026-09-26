import { expect, test } from "@playwright/test";
import { Pbkdf2Wrapper } from "../src-ts/password-hashers/pbkdf2-wrapper";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { areEqual } from "./helpers/array";

test.describe("PBKDF2 Tests", () => {
  test("derive with salt is deterministic", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const salt = Array.from(encoder.encode("SixteenByteSalt!"));
    const key1 = pbkdf2.deriveWithSalt(password, 1000, salt);
    const key2 = pbkdf2.deriveWithSalt(password, 1000, salt);
    expect(key1.length).toBe(32);
    expect(areEqual(key1, key2)).toBe(true);
  });

  test("derive returns a salt that reproduces the key", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const result = pbkdf2.derive(password, 1000);
    const rederived = pbkdf2.deriveWithSalt(password, 1000, result.salt);
    expect(areEqual(result.derivedKey, rederived)).toBe(true);
  });

  test("different salts produce different keys", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const key1 = pbkdf2.deriveWithSalt(password, 1000, Array.from(encoder.encode("SaltNumberOne===")));
    const key2 = pbkdf2.deriveWithSalt(password, 1000, Array.from(encoder.encode("SaltNumberTwo===")));
    expect(areEqual(key1, key2)).toBe(false);
  });

  test("different iteration counts produce different keys", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const salt = Array.from(encoder.encode("SixteenByteSalt!"));
    const key1 = pbkdf2.deriveWithSalt(password, 1000, salt);
    const key2 = pbkdf2.deriveWithSalt(password, 1001, salt);
    expect(areEqual(key1, key2)).toBe(false);
  });

  test("different passwords produce different keys", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const salt = Array.from(encoder.encode("SixteenByteSalt!"));
    const key1 = pbkdf2.deriveWithSalt(Array.from(encoder.encode("BadPassword")), 1000, salt);
    const key2 = pbkdf2.deriveWithSalt(Array.from(encoder.encode("BadPassword2")), 1000, salt);
    expect(areEqual(key1, key2)).toBe(false);
  });

  test("derive generates a fresh salt on every call", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const password = Array.from(new TextEncoder().encode("BadPassword"));
    const result1 = pbkdf2.derive(password, 1000);
    const result2 = pbkdf2.derive(password, 1000);
    expect(result1.derivedKey.length).toBe(32);
    expect(result1.salt.length).toBeGreaterThan(0);
    expect(areEqual(result1.salt, result2.salt)).toBe(false);
    expect(areEqual(result1.derivedKey, result2.derivedKey)).toBe(false);
  });

  test("derived key can be used as an AES-256-GCM key", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const aes = new AESWrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const key = aes.aes256KeyFromBytes(pbkdf2.derive(password, 1000).derivedKey);
    const nonce = aes.generateAESNonce();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    expect(areEqual(aes.aes256Decrypt(key, nonce, ciphertext), plaintext)).toBe(true);
  });
});
