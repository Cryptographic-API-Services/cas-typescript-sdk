import {test, expect } from '@playwright/test';
import { Argon2Wrapper, BCryptWrapper } from "../src-ts/password-hashers/index";
import { ScryptWrapper } from "../src-ts/password-hashers/index";
import {
  PasswordHasherFactory,
  PasswordHasherType,
} from "../src-ts/password-hashers";
import { AESWrapper } from "../src-ts/symmetric";

test.describe("Bcrypt Tests", () => {

  test("hash", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "ThisOneBadPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    expect(hashedPassword).not.toBe(password);
  });

  test("verify pass", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "NotThisPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    const isValid: boolean = hasher.verify(hashedPassword, password);
    expect(isValid).toBe(true);
  });

  test("verify fail", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "NotThisPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    const isValid: boolean = hasher.verify(
      hashedPassword,
      "ThesePasswordsDoNotMatch",
    );
    expect(isValid).toBe(false);
  });

  test("hash with params", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "ThisOneBadPassword!@";
    const hashedPassword: string = hasher.hashPasswordWithParameters(password, 12);
    expect(hashedPassword).not.toBe(password);
  })
});

test.describe("Scrypt Tests", () => {
  test("hash with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPassword(password);
    expect(hashed).not.toBe(password);
  });

  test("verify pass with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocks1231231";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(hashed, password);
    expect(verified).toBe(true);
  });

  test("verify fail with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocksSomeGarbageText";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(
      hashed,
      "make this fail, its not the same",
    );
    expect(verified).toBe(false);
  });

  test("hash with params", () => {
    const hasher: ScryptWrapper = new ScryptWrapper();
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPasswordWithParameters(password, 17, 8, 1);
    expect(hashed).not.toBe(password);
  });
});

test.describe("Argon2 Tests", () => { 
  test("hash with factory", () => {
    const hasher: Argon2Wrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPassword(password);
    expect(hashed).not.toBe(password);
  });

  test("verify pass with factory", () => {
    const hasher: Argon2Wrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocks1231231";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(hashed, password);
    expect(verified).toBe(true);
  });

  test("verify fail with factory", () => {
    const hasher: Argon2Wrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocksSomeGarbageText";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(
      hashed,
      "make this fail, its not the same",
    );
    expect(verified).toBe(false);
  });

  test("hash with params", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const password: string = "Argon2Rocks";
    const hashed: string = hasher.hashPasswordWithParameters(password, 1024, 3, 1);
    expect(hashed).not.toBe(password);
  });

  test("derive aes 128 key", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
    const key: number[] = hasher.deriveAes128Key(password);
    expect(key.length).toBe(16);
    // A random salt is generated per call, so the same password must not repeat a key.
    const secondKey: number[] = hasher.deriveAes128Key(password);
    expect(secondKey).not.toEqual(key);
  });

  test("derive aes 256 key", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
    const key: number[] = hasher.deriveAes256Key(password);
    expect(key.length).toBe(32);
    const secondKey: number[] = hasher.deriveAes256Key(password);
    expect(secondKey).not.toEqual(key);
  });

  test("derive aes 256 key encrypt and decrypt round trip", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const aes: AESWrapper = new AESWrapper();
    const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
    const key: number[] = hasher.deriveAes256Key(password);
    const nonce: number[] = aes.generateAESNonce();
    const plaintext: number[] = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext: number[] = aes.aes256Encrypt(key, nonce, plaintext);
    const decrypted: number[] = aes.aes256Decrypt(key, nonce, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });
});