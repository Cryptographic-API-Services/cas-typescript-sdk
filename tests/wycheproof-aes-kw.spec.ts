import { expect, test } from "@playwright/test";
import { AesKeyWrapWrapper } from "../src-ts/symmetric/aes-key-wrap-wrapper";
import {
  KeywrapTest,
  KeywrapTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

type KeyWrapFn = (kek: number[], data: number[]) => number[];

const SUPPORTED_KEY_SIZES = [128, 256];

const kw = new AesKeyWrapWrapper();

const MODES: Array<{
  name: string;
  file: string;
  wrap: Record<number, KeyWrapFn>;
  unwrap: Record<number, KeyWrapFn>;
}> = [
  {
    name: "AES-KW (RFC 3394)",
    file: "aes_wrap_test.json",
    wrap: { 128: kw.aes128WrapKey.bind(kw), 256: kw.aes256WrapKey.bind(kw) },
    unwrap: { 128: kw.aes128UnwrapKey.bind(kw), 256: kw.aes256UnwrapKey.bind(kw) },
  },
  {
    name: "AES-KWP (RFC 5649)",
    file: "aes_kwp_test.json",
    wrap: { 128: kw.aes128WrapKeyWithPadding.bind(kw), 256: kw.aes256WrapKeyWithPadding.bind(kw) },
    unwrap: { 128: kw.aes128UnwrapKeyWithPadding.bind(kw), 256: kw.aes256UnwrapKeyWithPadding.bind(kw) },
  },
];

function tryCall(fn: () => number[]): number[] | undefined {
  try {
    return fn();
  } catch {
    return undefined;
  }
}

test.describe("Wycheproof AES key wrap vectors", () => {
  for (const mode of MODES) {
    // cas-lib has no AES-192 KEK, so those groups are skipped and counted.
    test(`${mode.name} skips only the AES-192 groups`, () => {
      const file = loadWycheproof<KeywrapTestGroup>(mode.file);
      const skipped = file.testGroups.filter((group) => !SUPPORTED_KEY_SIZES.includes(group.keySize));
      const skippedVectors = skipped.reduce((sum, group) => sum + group.tests.length, 0);
      test.info().annotations.push({
        type: "skipped-vectors",
        description: `${skippedVectors} of ${file.numberOfTests} vectors in ${skipped.length} AES-192 group(s)`,
      });
      expect([...new Set(skipped.map((group) => group.keySize))]).toEqual([192]);
      expect(skippedVectors).toBeGreaterThan(0);
      expect(skippedVectors).toBeLessThan(file.numberOfTests);
    });

    for (const keySize of SUPPORTED_KEY_SIZES) {
      test(`AES-${keySize} ${mode.name} matches Wycheproof vectors`, () => {
        const wrap = mode.wrap[keySize];
        const unwrap = mode.unwrap[keySize];
        const file = loadWycheproof<KeywrapTestGroup>(mode.file);
        const vectors: KeywrapTest[] = file.testGroups
          .filter((group) => group.keySize === keySize)
          .flatMap((group) => group.tests);

        const counts = { valid: 0, invalid: 0, acceptable: 0 };
        for (const vector of vectors) {
          const label = `tcId ${vector.tcId} (${vector.comment}; ${vector.flags.join(", ")})`;
          const kek = hexToBytes(vector.key);
          const msg = hexToBytes(vector.msg);
          const ct = hexToBytes(vector.ct);
          counts[vector.result]++;

          if (vector.result === "valid") {
            expect(bytesToHex(wrap(kek, msg)), `${label}: wrapped key mismatch`).toBe(vector.ct);
            expect(bytesToHex(unwrap(kek, ct)), `${label}: unwrapped key mismatch`).toBe(vector.msg);
          } else if (vector.result === "invalid") {
            expect(() => unwrap(kek, ct), `${label}: unwrap accepted an invalid wrapped key`).toThrow();
            // An empty ct or msg means the key data itself must be rejected for wrapping.
            if (ct.length === 0 || msg.length === 0) {
              expect(() => wrap(kek, msg), `${label}: wrap accepted invalid key data`).toThrow();
            }
          } else {
            const unwrapped = tryCall(() => unwrap(kek, ct));
            if (unwrapped !== undefined) {
              expect(bytesToHex(unwrapped), `${label}: unwrapped key mismatch`).toBe(vector.msg);
            }
            const wrapped = tryCall(() => wrap(kek, msg));
            if (wrapped !== undefined) {
              expect(bytesToHex(wrapped), `${label}: wrapped key mismatch`).toBe(vector.ct);
            }
          }
        }

        test.info().annotations.push({
          type: "vectors",
          description: `${counts.valid} valid, ${counts.invalid} invalid, ${counts.acceptable} acceptable`,
        });
        expect(counts.valid, "no valid vectors found").toBeGreaterThan(0);
        expect(counts.invalid, "no invalid vectors found").toBeGreaterThan(0);
      });
    }
  }
});
