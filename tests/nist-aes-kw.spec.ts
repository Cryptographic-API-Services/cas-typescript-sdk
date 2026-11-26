import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { isCasError } from "../src-ts/errors";
import { AesKeyWrapWrapper } from "../src-ts/symmetric/aes-key-wrap-wrapper";
import { bytesToHex, hexToBytes, parseCavp, type CavpRecord } from "./helpers/cavp";

// CAVP kwtestvectors.zip, 128- and 256-bit KEK only. 500 records per file. #183.
const perFile = 500;

function load(fileName: string): CavpRecord[] {
  return parseCavp(fs.readFileSync(path.join(__dirname, "data", "nist", fileName), "utf8"));
}

test.describe("NIST CAVP AES-KW and AES-KWP", () => {
  test("wrap matches C, unwrap returns P, and FAIL vectors throw", () => {
    test.setTimeout(180_000);
    const wrap = new AesKeyWrapWrapper();
    const files = [
      ["KW_AE_128.txt", wrap.aes128WrapKey.bind(wrap), wrap.aes128UnwrapKey.bind(wrap)],
      ["KW_AE_256.txt", wrap.aes256WrapKey.bind(wrap), wrap.aes256UnwrapKey.bind(wrap)],
      ["KW_AD_128.txt", wrap.aes128WrapKey.bind(wrap), wrap.aes128UnwrapKey.bind(wrap)],
      ["KW_AD_256.txt", wrap.aes256WrapKey.bind(wrap), wrap.aes256UnwrapKey.bind(wrap)],
      ["KWP_AE_128.txt", wrap.aes128WrapKeyWithPadding.bind(wrap), wrap.aes128UnwrapKeyWithPadding.bind(wrap)],
      ["KWP_AE_256.txt", wrap.aes256WrapKeyWithPadding.bind(wrap), wrap.aes256UnwrapKeyWithPadding.bind(wrap)],
      ["KWP_AD_128.txt", wrap.aes128WrapKeyWithPadding.bind(wrap), wrap.aes128UnwrapKeyWithPadding.bind(wrap)],
      ["KWP_AD_256.txt", wrap.aes256WrapKeyWithPadding.bind(wrap), wrap.aes256UnwrapKeyWithPadding.bind(wrap)],
    ] as const;

    for (const [fileName, seal, open] of files) {
      const vectors = load(fileName);
      expect(vectors.length, fileName).toBe(perFile);
      const rejected = vectors.filter((vector) => vector.fail);
      if (fileName.includes("_AD_")) {
        expect(rejected.length, fileName).toBe(100);
      } else {
        expect(rejected.length, fileName).toBe(0);
      }

      for (const vector of vectors) {
        const kek = hexToBytes(vector.fields.K);
        const wrapped = hexToBytes(vector.fields.C);
        if (vector.fail) {
          expect(() => open(kek, wrapped), fileName).toThrow();
          try {
            open(kek, wrapped);
          } catch (error) {
            expect(isCasError(error)).toBe(true);
          }
          continue;
        }
        const plaintext = hexToBytes(vector.fields.P);
        if (fileName.includes("_AE_")) {
          expect(bytesToHex(seal(kek, plaintext)), fileName).toBe(vector.fields.C.toLowerCase());
        }
        expect(bytesToHex(open(kek, wrapped)), fileName).toBe(vector.fields.P.toLowerCase());
      }
    }
  });
});
