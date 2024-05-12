import { assert, expect } from "chai";
import { Argon2Wrapper, BCryptWrapper } from "../src-ts/password-hashers/index";
import { ScryptWrapper } from "../src-ts/password-hashers/index";
import {
  PasswordHasherFactory,
  PasswordHasherType,
} from "../src-ts/password-hashers";

describe("Bcrypt Tests", () => {
  it("hash", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "ThisOneBadPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    assert.notEqual(hashedPassword, password);
  });

  it("verify pass", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "NotThisPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    const isValid: boolean = hasher.verify(hashedPassword, password);
    expect(isValid).to.equal(true);
  });

  it("verify fail", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "NotThisPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    const isValid: boolean = hasher.verify(
      hashedPassword,
      "ThesePasswordsDoNotMatch",
    );
    expect(isValid).to.equal(false);
  });
});

describe("Scrypt Tests", () => {
  it("hash with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPassword(password);
    assert.notEqual(password, hashed);
  });

  it("verify pass with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocks1231231";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(hashed, password);
    assert.isTrue(verified);
  });

  it("verify fail with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocksSomeGarbageText";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(
      hashed,
      "make this fail, its not the same",
    );
    assert.isNotTrue(verified);
  });
});

describe("Argon2 Tests", () => {
  it("hash with threadpool", () => {
    const argon2: Argon2Wrapper = PasswordHasherFactory.getHasher(PasswordHasherType.Argon2);
    const password = "Argon2OverBCrypt";
    const hashed = argon2.hashPasswordThreadPool(password);
    assert.notEqual(password, hashed);
  })

  it("hash with factory", () => {
    const hasher: Argon2Wrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPassword(password);
    assert.notEqual(password, hashed);
  });

  it("verify pass with factory", () => {
    const hasher: Argon2Wrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocks1231231";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(hashed, password);
    assert.isTrue(verified);
  });

  it("verify fail with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Argon2,
    );
    const password: string = "ScryptRocksSomeGarbageText";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verify(
      hashed,
      "make this fail, its not the same",
    );
    assert.isNotTrue(verified);
  });
});