import { createCipheriv } from "node:crypto";
import { expect, test } from "@playwright/test";
import { AesKeyWrapWrapper } from "../src-ts/symmetric/aes-key-wrap-wrapper";
import { CasErrorCode, isCasError } from "../src-ts/errors";
import { bytesToHex, hexToBytes } from "./helpers/wycheproof";

const KEK_128 = "000102030405060708090a0b0c0d0e0f";
const KEK_256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const KEY_DATA_256 = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f";

function expectCasError(fn: () => unknown, code: CasErrorCode): void {
  let thrown: unknown;
  try {
    fn();
  } catch (err) {
    thrown = err;
  }
  expect(isCasError(thrown, code), `expected ${code}, got ${String(thrown)}`).toBe(true);
}

test.describe("AES key wrap Tests", () => {
  // RFC 3394 section 4. Sections 4.2 and 4.4 use a 192-bit KEK, which cas-lib does not support.
  const rfc3394 = [
    { section: "4.1", kek: KEK_128, data: KEY_DATA_256.slice(0, 32), ct: "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5" },
    { section: "4.3", kek: KEK_256, data: KEY_DATA_256.slice(0, 32), ct: "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7" },
    { section: "4.5", kek: KEK_256, data: KEY_DATA_256.slice(0, 48), ct: "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1" },
    { section: "4.6", kek: KEK_256, data: KEY_DATA_256, ct: "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21" },
  ];

  for (const vector of rfc3394) {
    test(`RFC 3394 section ${vector.section} vector wraps and unwraps`, () => {
      const kw = new AesKeyWrapWrapper();
      const kek = hexToBytes(vector.kek);
      const wrap = kek.length === 16 ? kw.aes128WrapKey.bind(kw) : kw.aes256WrapKey.bind(kw);
      const unwrap = kek.length === 16 ? kw.aes128UnwrapKey.bind(kw) : kw.aes256UnwrapKey.bind(kw);
      expect(bytesToHex(wrap(kek, hexToBytes(vector.data)))).toBe(vector.ct);
      expect(bytesToHex(unwrap(kek, hexToBytes(vector.ct)))).toBe(vector.data);
    });
  }

  // RFC 5649 section 6 only has vectors under a 192-bit KEK, which cas-lib does not support, so
  // its two key data inputs are wrapped under 128/256-bit KEKs and checked against OpenSSL's KWP.
  const rfc5649KeyData = ["c37b7e6492584340bed12207808941155068f738", "466f7250617369"];

  for (const keySize of [128, 256]) {
    test(`AES-${keySize}-KWP matches OpenSSL for the RFC 5649 section 6 key data`, () => {
      const kw = new AesKeyWrapWrapper();
      const kek = keySize === 128 ? kw.aes128GenerateKek() : kw.aes256GenerateKek();
      const wrap = keySize === 128 ? kw.aes128WrapKeyWithPadding.bind(kw) : kw.aes256WrapKeyWithPadding.bind(kw);
      const unwrap = keySize === 128 ? kw.aes128UnwrapKeyWithPadding.bind(kw) : kw.aes256UnwrapKeyWithPadding.bind(kw);
      for (const data of rfc5649KeyData) {
        const cipher = createCipheriv(`id-aes${keySize}-wrap-pad`, Buffer.from(kek), Buffer.from("a65959a6", "hex"));
        const expected = Buffer.concat([cipher.update(Buffer.from(data, "hex")), cipher.final()]).toString("hex");
        const wrapped = wrap(kek, hexToBytes(data));
        expect(bytesToHex(wrapped)).toBe(expected);
        expect(wrapped.length).toBe(Math.ceil(data.length / 16) * 8 + 8);
        expect(bytesToHex(unwrap(kek, wrapped))).toBe(data);
      }
    });
  }

  test("generated KEK sizes", () => {
    const kw = new AesKeyWrapWrapper();
    expect(kw.aes128GenerateKek().length).toBe(16);
    expect(kw.aes256GenerateKek().length).toBe(32);
  });

  test("tampered wrapped key fails to unwrap", () => {
    const kw = new AesKeyWrapWrapper();
    const kek128 = kw.aes128GenerateKek();
    const kek256 = kw.aes256GenerateKek();
    const key = kw.aes256GenerateKek();

    const cases: Array<[(kek: number[], data: number[]) => number[], (kek: number[], wrapped: number[]) => number[], number[], number[]]> = [
      [kw.aes128WrapKey.bind(kw), kw.aes128UnwrapKey.bind(kw), kek128, key],
      [kw.aes256WrapKey.bind(kw), kw.aes256UnwrapKey.bind(kw), kek256, key],
      [kw.aes128WrapKeyWithPadding.bind(kw), kw.aes128UnwrapKeyWithPadding.bind(kw), kek128, key.slice(0, 20)],
      [kw.aes256WrapKeyWithPadding.bind(kw), kw.aes256UnwrapKeyWithPadding.bind(kw), kek256, key.slice(0, 7)],
    ];
    for (const [wrap, unwrap, kek, data] of cases) {
      const wrapped = wrap(kek, data);
      for (const index of [0, wrapped.length - 1]) {
        const tampered = [...wrapped];
        tampered[index] ^= 0x01;
        expectCasError(() => unwrap(kek, tampered), CasErrorCode.DecryptionFailed);
      }
      const wrongKek = [...kek];
      wrongKek[0] ^= 0x01;
      expectCasError(() => unwrap(wrongKek, wrapped), CasErrorCode.DecryptionFailed);
    }
  });

  test("KW rejects key data that is not a multiple of 8 bytes", () => {
    const kw = new AesKeyWrapWrapper();
    const kek128 = kw.aes128GenerateKek();
    const kek256 = kw.aes256GenerateKek();
    for (const length of [17, 20, 31]) {
      const data = new Array(length).fill(0x42);
      expectCasError(() => kw.aes128WrapKey(kek128, data), CasErrorCode.InvalidInput);
      expectCasError(() => kw.aes256WrapKey(kek256, data), CasErrorCode.InvalidInput);
      expect(kw.aes256UnwrapKeyWithPadding(kek256, kw.aes256WrapKeyWithPadding(kek256, data))).toEqual(data);
    }
    expectCasError(() => kw.aes128WrapKey(kek128, new Array(8).fill(0x42)), CasErrorCode.InvalidInput);
    expectCasError(() => kw.aes128UnwrapKey(kek128, new Array(28).fill(0x42)), CasErrorCode.InvalidInput);
  });

  test("rejects empty key data, wrong KEK lengths and missing arguments", () => {
    const kw = new AesKeyWrapWrapper();
    const kek128 = kw.aes128GenerateKek();
    const kek256 = kw.aes256GenerateKek();
    const key = kw.aes128GenerateKek();
    expectCasError(() => kw.aes128WrapKeyWithPadding(kek128, []), CasErrorCode.InvalidInput);
    expectCasError(() => kw.aes256WrapKey(kek256, []), CasErrorCode.InvalidInput);
    expectCasError(() => kw.aes128WrapKey(kek256, key), CasErrorCode.InvalidKey);
    expectCasError(() => kw.aes256WrapKeyWithPadding(kek128, key), CasErrorCode.InvalidKey);

    const missing = undefined as unknown as number[];
    expect(() => kw.aes128WrapKey(missing, key)).toThrow("kek must be a byte array");
    expect(() => kw.aes256UnwrapKeyWithPadding(kek256, missing)).toThrow("wrappedKey must be a byte array");
  });
});
