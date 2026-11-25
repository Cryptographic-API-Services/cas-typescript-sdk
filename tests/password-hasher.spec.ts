import {test, expect } from '@playwright/test';
import { Argon2Wrapper, BCryptWrapper } from "../src-ts/password-hashers/index";
import { ScryptWrapper } from "../src-ts/password-hashers/index";
import {
  PasswordHasherFactory,
  PasswordHasherType,
} from "../src-ts/password-hashers";
import { AESWrapper } from "../src-ts/symmetric";
import { CasErrorCode, isCasError } from "../src-ts/index";
import { argon2HashParams, bcryptHashParams, scryptHashParams } from "../index";

// Cost 4 (below today's minimum of 10); from the bcrypt crate's tests.
const BCRYPT_COST_4_HASH = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
// log2 N = 8 (below today's minimum of 10), password "password"; made with Node's crypto.scryptSync.
const SCRYPT_LOG_N_8_HASH = "$scrypt$ln=8,r=8,p=1$Y2FzLXNkay1zY3J5cHQtbG44$we6PL3qFpfGm2MUwKWwoMg8sO/qJYxFio5fRYVWizCk";
// 256 KiB of memory (below today's minimum of 19 MiB), password "password"; Argon2 reference test vector.
const ARGON2_256_KIB_HASH = "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4";

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

  test("72 byte password hashes and verifies", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "a".repeat(72);
    const hashedPassword: string = hasher.hashPassword(password);
    expect(hasher.verify(hashedPassword, password)).toBe(true);
  });

  test("password over 72 bytes throws", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "a".repeat(73);
    expect(() => hasher.hashPassword(password)).toThrow(/72 bytes/);
    expect(() => hasher.hashPasswordWithParameters(password, 10)).toThrow(/72 bytes/);
    const hashedPassword: string = hasher.hashPasswordWithParameters(password.slice(0, 72), 10);
    expect(() => hasher.verify(hashedPassword, password)).toThrow(/72 bytes/);
  });

  test("password limit counts UTF-8 bytes, not characters", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const encoder = new TextEncoder();
    for (const char of ["é", "€", "😀"]) {
      const bytesPerChar = encoder.encode(char).length;
      const password = char.repeat(Math.floor(72 / bytesPerChar));
      expect(encoder.encode(password).length).toBe(72);
      const hashedPassword = hasher.hashPasswordWithParameters(password, 10);
      expect(hasher.verify(hashedPassword, password)).toBe(true);
      expect(() => hasher.hashPasswordWithParameters(password + "a", 10)).toThrow(/72 bytes/);
    }
  });

  test("cost bounds are 10 to 16", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    const password: string = "ThisOneBadPassword!@";
    for (const cost of [10, 16]) {
      const hashed = hasher.hashPasswordWithParameters(password, cost);
      expect(hashed.startsWith(`$2b$${cost}$`)).toBe(true);
      expect(hasher.verify(hashed, password)).toBe(true);
    }
    for (const cost of [9, 17, 4, 31, 12.5, NaN]) {
      expect(() => hasher.hashPasswordWithParameters(password, cost)).toThrow(/cost must be an integer from 10 to 16/);
    }
  });

  test("native layer enforces the cost bounds too", () => {
    expect(() => bcryptHashParams(9, "ThisOneBadPassword!@")).toThrow();
    expect(() => bcryptHashParams(17, "ThisOneBadPassword!@")).toThrow();
  });

  test("hashes below the minimum cost still verify", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    expect(hasher.verify(BCRYPT_COST_4_HASH, "correctbatteryhorsestapler")).toBe(true);
    expect(hasher.verify(BCRYPT_COST_4_HASH, "wrong")).toBe(false);
  });

  test("verify refuses stored hashes above the maximum cost", () => {
    const hasher: BCryptWrapper = new BCryptWrapper();
    for (const cost of ["17", "31"]) {
      const hostile = BCRYPT_COST_4_HASH.replace("$04$", `$${cost}$`);
      expect(() => hasher.verify(hostile, "correctbatteryhorsestapler")).toThrow();
    }
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

  test("hash with params", () => {
    const hasher: ScryptWrapper = new ScryptWrapper();
    const password: string = "ScryptRocks";
    const hashed: string = hasher.hashPasswordWithParameters(password, 17, 8, 1);
    expect(hashed).not.toBe(password);
  });

  test("parameter bounds: log2 N 10-20, r 1-32, p 1-16", () => {
    const hasher: ScryptWrapper = new ScryptWrapper();
    const password: string = "ScryptRocks";
    const atBounds: Array<[number, number, number]> = [
      [10, 1, 1],
      [20, 2, 1],
      [10, 32, 1],
      [10, 1, 16],
    ];
    for (const [logN, r, p] of atBounds) {
      const hashed = hasher.hashPasswordWithParameters(password, logN, r, p);
      expect(hashed.startsWith(`$scrypt$ln=${logN},r=${r},p=${p}$`)).toBe(true);
      expect(hasher.verify(hashed, password)).toBe(true);
    }
    expect(() => hasher.hashPasswordWithParameters(password, 9, 8, 1)).toThrow(/cpu cost \(log2 N\) must be an integer from 10 to 20/);
    expect(() => hasher.hashPasswordWithParameters(password, 21, 8, 1)).toThrow(/cpu cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 15.5, 8, 1)).toThrow(/cpu cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 15, 0, 1)).toThrow(/block size must be an integer from 1 to 32/);
    expect(() => hasher.hashPasswordWithParameters(password, 15, 33, 1)).toThrow(/block size/);
    expect(() => hasher.hashPasswordWithParameters(password, 15, 8, 0)).toThrow(/parallelism must be an integer from 1 to 16/);
    expect(() => hasher.hashPasswordWithParameters(password, 15, 8, 17)).toThrow(/parallelism/);
    expect(() => hasher.hashPasswordWithParameters(password, 16, 1, 1)).toThrow(/less than 16 \* block size/);
  });

  test("native layer enforces the parameter bounds too", () => {
    expect(() => scryptHashParams("ScryptRocks", 9, 8, 1)).toThrow();
    expect(() => scryptHashParams("ScryptRocks", 21, 8, 1)).toThrow();
    expect(() => scryptHashParams("ScryptRocks", 15, 33, 1)).toThrow();
    expect(() => scryptHashParams("ScryptRocks", 15, 8, 17)).toThrow();
  });

  test("hashes below the minimum cost still verify", () => {
    const hasher: ScryptWrapper = new ScryptWrapper();
    expect(hasher.verify(SCRYPT_LOG_N_8_HASH, "password")).toBe(true);
    expect(hasher.verify(SCRYPT_LOG_N_8_HASH, "wrong")).toBe(false);
  });

  test("verify refuses stored hashes above the maximum costs", () => {
    const hasher: ScryptWrapper = new ScryptWrapper();
    for (const params of ["ln=21,r=8,p=1", "ln=8,r=33,p=1", "ln=8,r=8,p=17"]) {
      const hostile = SCRYPT_LOG_N_8_HASH.replace("ln=8,r=8,p=1", params);
      expect(() => hasher.verify(hostile, "password")).toThrow();
    }
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
    const hashed: string = hasher.hashPasswordWithParameters(password, 19, 3, 1);
    expect(hashed).not.toBe(password);
  });

  test("parameter bounds: memory 19-4096 MiB, iterations 1-10, parallelism 1-16", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const password: string = "Argon2Rocks";
    // The 4096 MiB upper bound is checked only from the rejecting side: a 4 GiB
    // hash per test worker is too much for CI runners.
    const atBounds: Array<[number, number, number]> = [
      [19, 1, 1],
      [19, 10, 1],
      [19, 1, 16],
    ];
    for (const [memory, iterations, parallelism] of atBounds) {
      const hashed = hasher.hashPasswordWithParameters(password, memory, iterations, parallelism);
      // The memory cost is MiB, so the PHC string records it in KiB.
      expect(hashed).toContain(`$m=${memory * 1024},t=${iterations},p=${parallelism}$`);
      expect(hasher.verify(hashed, password)).toBe(true);
    }
    expect(() => hasher.hashPasswordWithParameters(password, 18, 2, 1)).toThrow(/memory cost \(MiB\) must be an integer from 19 to 4096/);
    expect(() => hasher.hashPasswordWithParameters(password, 4097, 2, 1)).toThrow(/memory cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 19456, 2, 1)).toThrow(/memory cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 19.5, 2, 1)).toThrow(/memory cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 19, 0, 1)).toThrow(/time cost must be an integer from 1 to 10/);
    expect(() => hasher.hashPasswordWithParameters(password, 19, 11, 1)).toThrow(/time cost/);
    expect(() => hasher.hashPasswordWithParameters(password, 19, 2, 0)).toThrow(/parallelism must be an integer from 1 to 16/);
    expect(() => hasher.hashPasswordWithParameters(password, 19, 2, 17)).toThrow(/parallelism/);
  });

  test("native layer enforces the parameter bounds too", () => {
    expect(() => argon2HashParams(18, 2, 1, "Argon2Rocks")).toThrow();
    expect(() => argon2HashParams(4097, 2, 1, "Argon2Rocks")).toThrow();
    expect(() => argon2HashParams(4194305, 2, 1, "Argon2Rocks")).toThrow();
    expect(() => argon2HashParams(19, 11, 1, "Argon2Rocks")).toThrow();
    expect(() => argon2HashParams(19, 2, 17, "Argon2Rocks")).toThrow();
  });

  test("hashes below the minimum cost still verify", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    expect(hasher.verify(ARGON2_256_KIB_HASH, "password")).toBe(true);
    expect(hasher.verify(ARGON2_256_KIB_HASH, "wrong")).toBe(false);
  });

  test("verify refuses stored hashes above the maximum costs", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    // 4096 MiB + 1 KiB, 11 iterations, parallelism 17.
    for (const params of ["m=4194305,t=2,p=1", "m=256,t=11,p=1", "m=256,t=2,p=17"]) {
      const hostile = ARGON2_256_KIB_HASH.replace("m=256,t=2,p=1", params);
      expect(() => hasher.verify(hostile, "password")).toThrow();
    }
  });

  test("generate salt", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const salt: number[] = hasher.generateSalt();
    expect(salt.length).toBe(16);
    expect(hasher.generateSalt()).not.toEqual(salt);
  });

  for (const [bits, keyLength] of [[128, 16], [256, 32]] as const) {
    const derive = (hasher: Argon2Wrapper, password: number[], salt: number[]): number[] =>
      bits === 128 ? hasher.deriveAes128KeyWithSalt(password, salt) : hasher.deriveAes256KeyWithSalt(password, salt);

    test(`derive aes ${bits} key with salt: same password and salt give the same key`, () => {
      const hasher: Argon2Wrapper = new Argon2Wrapper();
      const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
      const salt: number[] = hasher.generateSalt();
      const key: number[] = derive(hasher, password, salt);
      expect(key.length).toBe(keyLength);
      expect(derive(hasher, password, [...salt])).toEqual(key);
    });

    test(`derive aes ${bits} key with salt: a different salt gives a different key`, () => {
      const hasher: Argon2Wrapper = new Argon2Wrapper();
      const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
      const key: number[] = derive(hasher, password, hasher.generateSalt());
      expect(derive(hasher, password, hasher.generateSalt())).not.toEqual(key);
    });

    test(`derive aes ${bits} key with salt: a 15 byte salt throws CAS_INVALID_PARAMETERS`, () => {
      const hasher: Argon2Wrapper = new Argon2Wrapper();
      const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
      let caught: unknown;
      try {
        derive(hasher, password, new Array(15).fill(0));
      } catch (err) {
        caught = err;
      }
      expect(isCasError(caught, CasErrorCode.InvalidParameters)).toBe(true);
      expect(derive(hasher, password, new Array(16).fill(0)).length).toBe(keyLength);
    });
  }

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

  test("derive aes 256 key with salt encrypt and decrypt round trip", () => {
    const hasher: Argon2Wrapper = new Argon2Wrapper();
    const aes: AESWrapper = new AESWrapper();
    const password: number[] = Array.from(new TextEncoder().encode("Argon2Rocks"));
    const salt: number[] = hasher.generateSalt();
    const nonce: number[] = aes.generateAESNonce();
    const plaintext: number[] = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext: number[] = aes.aes256Encrypt(hasher.deriveAes256KeyWithSalt(password, salt), nonce, plaintext);
    // Re-derive the key from the stored salt to decrypt.
    const decrypted: number[] = aes.aes256Decrypt(hasher.deriveAes256KeyWithSalt(password, salt), nonce, ciphertext);
    expect(decrypted).toEqual(plaintext);
  });
});