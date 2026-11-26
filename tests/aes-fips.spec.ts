import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { CasErrorCode, isCasError } from "../src-ts/errors";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { bytesToHex, hexToBytes, parseCavp, type CavpRecord } from "./helpers/cavp";

const dataDir = path.join(__dirname, "data", "nist");

function load(fileName: string): CavpRecord[] {
  return parseCavp(fs.readFileSync(path.join(dataDir, fileName), "utf8"));
}

function usable(records: CavpRecord[]): CavpRecord[] {
  return records.filter((record) => record.section.IVlen === "96" && record.section.Taglen === "128");
}

function ctAndTag(record: CavpRecord): number[] {
  return hexToBytes(record.fields.CT + record.fields.Tag);
}

test.describe("NIST CAVP AES-GCM", () => {
  // gcmEncryptExtIV{128,256}.rsp and gcmDecrypt{128,256}.rsp, IVlen 96 / Taglen 128.
  // 375 records per file, from gcmtestvectors.zip. #183.
  const perFile = 375;

  test("AES-128 and AES-256 encrypt match CT‖Tag, including AAD and empty plaintext", () => {
    test.setTimeout(180_000);
    const aes = new AESWrapper();
    for (const [fileName, encrypt] of [
      ["gcmEncryptExtIV128.rsp", aes.aes128EncryptWithAad.bind(aes)],
      ["gcmEncryptExtIV256.rsp", aes.aes256EncryptWithAad.bind(aes)],
    ] as const) {
      const vectors = usable(load(fileName));
      expect(vectors.length, fileName).toBe(perFile);
      expect(vectors.some((vector) => vector.fields.AAD.length > 0)).toBe(true);
      expect(vectors.some((vector) => vector.fields.PT.length === 0)).toBe(true);
      for (const vector of vectors) {
        const actual = encrypt(
          hexToBytes(vector.fields.Key),
          hexToBytes(vector.fields.IV),
          hexToBytes(vector.fields.PT),
          hexToBytes(vector.fields.AAD),
        );
        expect(bytesToHex(actual), `${fileName} Count uses a full CT‖Tag`).toBe(
          (vector.fields.CT + vector.fields.Tag).toLowerCase(),
        );
      }
    }
  });

  test("AES-128 and AES-256 decrypt return PT, and FAIL vectors throw", () => {
    test.setTimeout(180_000);
    const aes = new AESWrapper();
    for (const [fileName, decrypt] of [
      ["gcmDecrypt128.rsp", aes.aes128DecryptWithAad.bind(aes)],
      ["gcmDecrypt256.rsp", aes.aes256DecryptWithAad.bind(aes)],
    ] as const) {
      const vectors = usable(load(fileName));
      expect(vectors.length, fileName).toBe(perFile);
      const rejected = vectors.filter((vector) => vector.fail);
      expect(rejected.length, fileName).toBeGreaterThan(0);
      for (const vector of vectors) {
        const open = () =>
          decrypt(
            hexToBytes(vector.fields.Key),
            hexToBytes(vector.fields.IV),
            ctAndTag(vector),
            hexToBytes(vector.fields.AAD),
          );
        if (vector.fail) {
          expect(open, `${fileName} FAIL`).toThrow();
          try {
            open();
          } catch (error) {
            expect(isCasError(error)).toBe(true);
          }
        } else {
          expect(bytesToHex(open())).toBe(vector.fields.PT.toLowerCase());
        }
      }
    }
  });

  test("a nonce that is not 12 bytes is rejected, and so is a truncated tag", () => {
    const aes = new AESWrapper();
    const records = load("gcmEncryptExtIV128.rsp");
    const badNonce = records.filter((record) => record.section.IVlen !== "96" && record.section.Taglen === "128");
    expect(badNonce.length).toBeGreaterThan(0);
    const sample = badNonce[0];
    expect(() =>
      aes.aes128EncryptWithAad(
        hexToBytes(sample.fields.Key),
        hexToBytes(sample.fields.IV),
        hexToBytes(sample.fields.PT),
        hexToBytes(sample.fields.AAD),
      ),
    ).toThrow();
    try {
      aes.aes128EncryptWithAad(
        hexToBytes(sample.fields.Key),
        hexToBytes(sample.fields.IV),
        hexToBytes(sample.fields.PT),
        hexToBytes(sample.fields.AAD),
      );
    } catch (error) {
      expect(isCasError(error, CasErrorCode.InvalidNonce)).toBe(true);
    }

    const valid = usable(load("gcmDecrypt128.rsp")).find((record) => !record.fail);
    if (!valid) {
      throw new Error("expected a valid AES-GCM decrypt vector");
    }
    const shortTag = ctAndTag(valid).slice(0, -1);
    expect(() =>
      aes.aes128DecryptWithAad(
        hexToBytes(valid.fields.Key),
        hexToBytes(valid.fields.IV),
        shortTag,
        hexToBytes(valid.fields.AAD),
      ),
    ).toThrow();
  });
});
