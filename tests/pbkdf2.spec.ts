import { expect, test } from "@playwright/test";
import { pbkdf2Derive, pbkdf2DeriveWithSalt } from "../index";
import { Pbkdf2Wrapper } from "../src-ts/password-hashers/pbkdf2-wrapper";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { areEqual } from "./helpers/array";

const MIN_ITERATIONS = 600_000;

// Every derivation at MIN_ITERATIONS is slow and each test runs once per
// Playwright project, so the success cases share as few calls as possible.
test.describe("PBKDF2 Tests", () => {
  test("derive returns a fresh salt that reproduces a usable key", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const result1 = pbkdf2.derive(password, MIN_ITERATIONS);
    const result2 = pbkdf2.derive(password, MIN_ITERATIONS);
    expect(result1.derivedKey.length).toBe(32);
    expect(result1.salt.length).toBeGreaterThanOrEqual(16);
    expect(areEqual(result1.salt, result2.salt)).toBe(false);
    expect(areEqual(result1.derivedKey, result2.derivedKey)).toBe(false);

    const rederived = pbkdf2.deriveWithSalt(password, MIN_ITERATIONS, result1.salt);
    expect(areEqual(result1.derivedKey, rederived)).toBe(true);

    const aes = new AESWrapper();
    const key = aes.aes256KeyFromBytes(result1.derivedKey);
    const nonce = aes.generateAESNonce();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    expect(areEqual(aes.aes256Decrypt(key, nonce, ciphertext), plaintext)).toBe(true);
  });

  test("changing the password, salt or iteration count changes the key", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const encoder = new TextEncoder();
    const password = Array.from(encoder.encode("BadPassword"));
    const salt = Array.from(encoder.encode("SixteenByteSalt!"));
    const key = pbkdf2.deriveWithSalt(password, MIN_ITERATIONS, salt);
    expect(key.length).toBe(32);
    const otherPassword = pbkdf2.deriveWithSalt(Array.from(encoder.encode("BadPassword2")), MIN_ITERATIONS, salt);
    const otherSalt = pbkdf2.deriveWithSalt(password, MIN_ITERATIONS, Array.from(encoder.encode("SaltNumberTwo===")));
    const otherIterations = pbkdf2.deriveWithSalt(password, MIN_ITERATIONS + 1, salt);
    expect(areEqual(key, otherPassword)).toBe(false);
    expect(areEqual(key, otherSalt)).toBe(false);
    expect(areEqual(key, otherIterations)).toBe(false);
  });

  test("rejects fewer than 600,000 iterations", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const password = Array.from(new TextEncoder().encode("BadPassword"));
    const salt = Array.from(new TextEncoder().encode("SixteenByteSalt!"));
    expect(() => pbkdf2.derive(password, MIN_ITERATIONS - 1)).toThrow(/600000/);
    expect(() => pbkdf2.deriveWithSalt(password, MIN_ITERATIONS - 1, salt)).toThrow(/600000/);
    expect(() => pbkdf2.deriveWithSalt(password, MIN_ITERATIONS + 0.5, salt)).toThrow(/600000/);
  });

  test("rejects a salt shorter than 16 bytes", () => {
    const pbkdf2 = new Pbkdf2Wrapper();
    const password = Array.from(new TextEncoder().encode("BadPassword"));
    const salt = Array.from(new TextEncoder().encode("FifteenByteSalt"));
    expect(salt.length).toBe(15);
    expect(() => pbkdf2.deriveWithSalt(password, MIN_ITERATIONS, salt)).toThrow(/16 bytes/);
  });

  test("native binding rejects weak parameters too", () => {
    const password = Array.from(new TextEncoder().encode("BadPassword"));
    const salt = Array.from(new TextEncoder().encode("SixteenByteSalt!"));
    expect(() => pbkdf2Derive(password, MIN_ITERATIONS - 1)).toThrow();
    expect(() => pbkdf2DeriveWithSalt(password, MIN_ITERATIONS - 1, salt)).toThrow();
    expect(() => pbkdf2DeriveWithSalt(password, MIN_ITERATIONS, salt.slice(0, 15))).toThrow();
  });
});
