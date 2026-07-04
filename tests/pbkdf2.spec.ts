import { expect, test } from "@playwright/test";
import { Pbkdf2Wrapper } from "../src-ts/password-hashers/pbkdf2-wrapper";
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
});
