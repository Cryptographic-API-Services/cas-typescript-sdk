import { assert, expect } from "chai";
import { BCryptWrapper } from "../src-ts/password-hashers/index";
import { ScryptWrapper } from "../src-ts/password-hashers/index";
import {
  PasswordHasherFactory,
  PasswordHasherType,
} from "../src-ts/password-hashers/";

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
    const isValid: boolean = hasher.verifyPassword(hashedPassword, password);
    expect(isValid).to.equal(true);
  });

  it("verify fail", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "NotThisPassword!@";
    const hashedPassword: string = hasher.hashPassword(password);
    const isValid: boolean = hasher.verifyPassword(
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
    const verified: boolean = hasher.verifyPassword(hashed, password);
    assert.isTrue(verified);
  });

  it("verify fail with factory", () => {
    const hasher: ScryptWrapper = PasswordHasherFactory.getHasher(
      PasswordHasherType.Scrypt,
    );
    const password: string = "ScryptRocksSomeGarbageText";
    const hashed: string = hasher.hashPassword(password);
    const verified: boolean = hasher.verifyPassword(
      hashed,
      "make this fail, its not the same",
    );
    assert.isNotTrue(verified);
  });
});
