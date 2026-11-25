import { expect, test } from "@playwright/test";
import { argon2HashParams } from "../index";
import {
  AESWrapper,
  Argon2Wrapper,
  CasErrorCode,
  Ed25519Wrapper,
  isCasError,
  MlKem1024Wrapper,
  RSAWrapper,
  ZTSDWrapper,
} from "../src-ts/index";

const toBytes = (text: string): Array<number> => Array.from(new TextEncoder().encode(text));

function expectCasError(fn: () => unknown, code: CasErrorCode, message: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(Error);
  expect((caught as Error & { code?: unknown }).code).toBe(code);
  expect((caught as Error).message).toBe(message);
  expect(isCasError(caught)).toBe(true);
  expect(isCasError(caught, code)).toBe(true);
}

test.describe("Typed CasError codes", () => {
  test("wrong key length throws CAS_INVALID_KEY", () => {
    const aes = new AESWrapper();
    expectCasError(
      () => aes.aes128Encrypt([1, 2, 3, 4, 5], aes.generateAESNonce(), toBytes("data")),
      CasErrorCode.InvalidKey,
      "invalid key: wrong length or could not be parsed",
    );
  });

  test("wrong nonce length throws CAS_INVALID_NONCE", () => {
    const aes = new AESWrapper();
    expectCasError(
      () => aes.aes128Encrypt(aes.aes128Key(), [1, 2, 3], toBytes("data")),
      CasErrorCode.InvalidNonce,
      "invalid nonce: wrong length",
    );
  });

  test("wrong signature length throws CAS_INVALID_SIGNATURE", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    expectCasError(
      () => ed25519.verifyBytes(keyPair.publicKey, toBytes("message"), [1, 2, 3]),
      CasErrorCode.InvalidSignature,
      "invalid signature: wrong length or could not be parsed",
    );
  });

  test("wrong ML-KEM ciphertext length throws CAS_INVALID_INPUT", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    expectCasError(
      () => mlKem.decapsulate(keyPair.secretKey, new Array(10).fill(0)),
      CasErrorCode.InvalidInput,
      "invalid input: could not be decoded",
    );
  });

  test("malformed RSA PEM key throws CAS_INVALID_PEM_KEY", () => {
    expectCasError(
      () => new RSAWrapper().sign("not a PEM key", toBytes("data")),
      CasErrorCode.InvalidPemKey,
      "invalid PEM key: could not be decoded or encoded",
    );
  });

  test("out-of-range Argon2 parameters throw CAS_INVALID_PARAMETERS", () => {
    // Argon2Wrapper rejects these bounds itself with a plain Error, so call the native binding.
    expectCasError(
      () => argon2HashParams(19, 0, 1, "password"),
      CasErrorCode.InvalidParameters,
      "invalid algorithm parameters",
    );
  });

  test("tampered ciphertext throws CAS_DECRYPTION_FAILED", () => {
    const aes = new AESWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateAESNonce();
    const ciphertext = aes.aes256Encrypt(key, nonce, toBytes("data"));
    ciphertext[0] ^= 0x01;
    expectCasError(
      () => aes.aes256Decrypt(key, nonce, ciphertext),
      CasErrorCode.DecryptionFailed,
      "decryption failed or authentication tag mismatch",
    );
  });

  test("unparseable password hash throws CAS_PASSWORD_HASHING_FAILED", () => {
    expectCasError(
      () => new Argon2Wrapper().verify("not a PHC hash string", "password"),
      CasErrorCode.PasswordHashingFailed,
      "password hashing failed",
    );
  });

  test("corrupt zstd data throws CAS_COMPRESSION_FAILED", () => {
    expectCasError(
      () => new ZTSDWrapper().decompress([1, 2, 3, 4, 5, 6, 7, 8]),
      CasErrorCode.CompressionFailed,
      "compression or decompression failed",
    );
  });

  test("zstd output over the limit throws CAS_DECOMPRESSION_LIMIT_EXCEEDED", () => {
    const zstd = new ZTSDWrapper();
    const compressed = zstd.compress(new Array(1024).fill(0), 3);
    expectCasError(
      () => zstd.decompress(compressed, 1023),
      CasErrorCode.DecompressionLimitExceeded,
      "decompressed output exceeds the size limit",
    );
  });

  test("isCasError rejects wrapper validation errors, other codes and non-errors", () => {
    let validationError: unknown;
    try {
      new ZTSDWrapper().decompress([]);
    } catch (err) {
      validationError = err;
    }
    expect(validationError).toBeInstanceOf(Error);
    expect(isCasError(validationError)).toBe(false);

    let decryptionError: unknown;
    const aes = new AESWrapper();
    try {
      aes.aes128Decrypt(aes.aes128Key(), aes.generateAESNonce(), new Array(32).fill(0));
    } catch (err) {
      decryptionError = err;
    }
    expect(isCasError(decryptionError, CasErrorCode.DecryptionFailed)).toBe(true);
    expect(isCasError(decryptionError, CasErrorCode.InvalidKey)).toBe(false);

    expect(isCasError({ code: CasErrorCode.InvalidKey, message: "not an Error" })).toBe(false);
    expect(isCasError(Object.assign(new Error("x"), { code: "ERR_SOMETHING_ELSE" }))).toBe(false);
    expect(isCasError(undefined)).toBe(false);
  });
});
