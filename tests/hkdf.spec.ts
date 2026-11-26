import { hkdfSync, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { CasErrorCode, HkdfWrapper, isCasError } from "../src-ts/index";

const hkdf = new HkdfWrapper();
const hex = (text: string): number[] => Array.from(Buffer.from(text, "hex"));
const bytes = (length: number): number[] => Array.from(randomBytes(length));

function expectCode(fn: () => unknown, code: CasErrorCode): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(isCasError(caught, code)).toBe(true);
}

// RFC 5869 Appendix A, test cases 1-3 (HKDF-SHA256).
const rfc5869 = [
  {
    ikm: "0b".repeat(22),
    salt: "000102030405060708090a0b0c",
    info: "f0f1f2f3f4f5f6f7f8f9",
    length: 42,
    prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
  },
  {
    ikm: Buffer.from(Array.from({ length: 0x50 }, (_, i) => i)).toString("hex"),
    salt: Buffer.from(Array.from({ length: 0x50 }, (_, i) => 0x60 + i)).toString("hex"),
    info: Buffer.from(Array.from({ length: 0x50 }, (_, i) => 0xb0 + i)).toString("hex"),
    length: 82,
    prk: "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
    okm:
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
      "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
      "cc30c58179ec3e87c14c01d5c1f3434f1d87",
  },
  {
    ikm: "0b".repeat(22),
    salt: "",
    info: "",
    length: 42,
    prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
    okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
  },
];

test.describe("HKDF", () => {
  test("RFC 5869 HKDF-SHA256 test cases", () => {
    for (const tc of rfc5869) {
      const prk = hkdf.hkdfSha256Extract(hex(tc.salt), hex(tc.ikm));
      expect(prk).toEqual(hex(tc.prk));
      expect(hkdf.hkdfSha256Expand(prk, hex(tc.info), tc.length)).toEqual(hex(tc.okm));
      expect(hkdf.hkdfSha256Derive(hex(tc.salt), hex(tc.ikm), hex(tc.info), tc.length)).toEqual(hex(tc.okm));
    }
  });

  test("matches node:crypto hkdfSync for SHA-256 and SHA-512", () => {
    const cases = [
      { hash: "sha256", extract: hkdf.hkdfSha256Extract, expand: hkdf.hkdfSha256Expand, derive: hkdf.hkdfSha256Derive, max: 8160 },
      { hash: "sha512", extract: hkdf.hkdfSha512Extract, expand: hkdf.hkdfSha512Expand, derive: hkdf.hkdfSha512Derive, max: 16320 },
    ];
    for (const { hash, extract, expand, derive, max } of cases) {
      for (const length of [1, 32, 64, 100, max]) {
        const ikm = bytes(97);
        const salt = bytes(64);
        const info = bytes(40);
        const expected = Array.from(new Uint8Array(hkdfSync(hash, Buffer.from(ikm), Buffer.from(salt), Buffer.from(info), length)));
        expect(derive.call(hkdf, salt, ikm, info, length)).toEqual(expected);
        expect(expand.call(hkdf, extract.call(hkdf, salt, ikm), info, length)).toEqual(expected);
      }
    }
  });

  test("one PRK expands to independent keys per info", () => {
    const prk = hkdf.hkdfSha512Extract(bytes(64), bytes(96));
    expect(prk).toHaveLength(64);
    const send = hkdf.hkdfSha512Expand(prk, [1, 2, 3], 32);
    const receive = hkdf.hkdfSha512Expand(prk, [4, 5, 6], 32);
    expect(send).toHaveLength(32);
    expect(send).not.toEqual(receive);
    expect(hkdf.hkdfSha512Expand(prk, [1, 2, 3], 32)).toEqual(send);
  });

  test("null, undefined and empty salt / info are the same", () => {
    const ikm = bytes(32);
    const zeroSalt = hkdf.hkdfSha512Extract(new Array(64).fill(0), ikm);
    for (const empty of [null, undefined, []]) {
      expect(hkdf.hkdfSha512Extract(empty, ikm)).toEqual(zeroSalt);
      expect(hkdf.hkdfSha256Derive(empty, ikm, empty, 32)).toEqual(hkdf.hkdfSha256Derive([], ikm, [], 32));
    }
  });

  test("rejects bad lengths and short PRKs with CasError codes", () => {
    expectCode(() => hkdf.hkdfSha256Expand(bytes(32), [], 0), CasErrorCode.InvalidParameters);
    expectCode(() => hkdf.hkdfSha256Expand(bytes(32), [], 8161), CasErrorCode.InvalidParameters);
    expectCode(() => hkdf.hkdfSha512Derive([], bytes(32), [], 16321), CasErrorCode.InvalidParameters);
    expectCode(() => hkdf.hkdfSha256Expand(bytes(31), [], 32), CasErrorCode.InvalidKey);
    expectCode(() => hkdf.hkdfSha512Expand(bytes(63), [], 32), CasErrorCode.InvalidKey);
  });

  test("rejects lengths that are not non-negative integers before the native call", () => {
    for (const length of [-1, 1.5, Number.NaN, 2 ** 32]) {
      expect(() => hkdf.hkdfSha256Expand(bytes(32), [], length)).toThrow("length must be a non-negative integer");
      expect(() => hkdf.hkdfSha512Derive([], bytes(32), [], length)).toThrow("length must be a non-negative integer");
    }
  });
});
