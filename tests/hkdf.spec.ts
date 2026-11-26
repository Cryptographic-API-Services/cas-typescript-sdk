import { hkdfSync, randomBytes } from "node:crypto";
import { expect, test } from "@playwright/test";
import { CasErrorCode, HkdfWrapper, isCasError } from "../src-ts/index";

const hkdf = new HkdfWrapper();
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

// Known answers come from the Wycheproof files (tests/wycheproof-hkdf.spec.ts) and
// node:crypto's hkdfSync. Inputs are random: CodeQL flags literal salts and keys.

test.describe("HKDF", () => {
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

  test("null, undefined and empty salt / info mean none, as in node:crypto", () => {
    const ikm = bytes(32);
    const empty = Buffer.alloc(0);
    const expected256 = Array.from(new Uint8Array(hkdfSync("sha256", Buffer.from(ikm), empty, empty, 32)));
    const expected512 = Array.from(new Uint8Array(hkdfSync("sha512", Buffer.from(ikm), empty, empty, 32)));
    for (const none of [null, undefined, []]) {
      expect(hkdf.hkdfSha256Derive(none, ikm, none, 32)).toEqual(expected256);
      expect(hkdf.hkdfSha512Derive(none, ikm, none, 32)).toEqual(expected512);
      expect(hkdf.hkdfSha512Expand(hkdf.hkdfSha512Extract(none, ikm), none, 32)).toEqual(expected512);
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
