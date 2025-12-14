import {test, expect } from '@playwright/test';
import { assert } from "chai";
import { Argon2Wrapper, BCryptWrapper } from "../src-ts/password-hashers/index";
import { ScryptWrapper } from "../src-ts/password-hashers/index";
import {
  PasswordHasherFactory,
  PasswordHasherType,
} from "../src-ts/password-hashers";

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
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
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
});