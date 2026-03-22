import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";

type AesFipsVector = {
  key: number[];
  iv: number[];
  plaintext: number[];
  expectedCiphertext: number[];
};

function hexToBytes(hex: string): number[] {
  if (!hex) {
    return [];
  }

  return Array.from(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes: number[]): string {
  return Buffer.from(bytes).toString("hex");
}

function parseGcmEncryptVectors(fileName: string): AesFipsVector[] {
  const filePath = path.join(__dirname, "data", "aes", fileName);
  const contents = fs.readFileSync(filePath, "utf8");
  const lines = contents.split(/\r?\n/);
  const vectors: AesFipsVector[] = [];

  let ivLen = -1;
  let aadLen = -1;
  let keyHex: string | null = null;
  let ivHex: string | null = null;
  let ctHex: string | null = null;
  let ptHex: string | null = null;
  let isFailureCase = false;

  for (const line of lines) {
    const trimmed = line.trim();
    let match: RegExpMatchArray | null = null;

    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    if ((match = trimmed.match(/^\[IVlen = (\d+)\]$/))) {
      ivLen = Number(match[1]);
      continue;
    }

    if ((match = trimmed.match(/^\[AADlen = (\d+)\]$/))) {
      aadLen = Number(match[1]);
      continue;
    }

    if (trimmed.startsWith("[")) {
      continue;
    }

    if (trimmed.startsWith("Count =")) {
      keyHex = null;
      ivHex = null;
      ctHex = null;
      ptHex = null;
      isFailureCase = false;
      continue;
    }

    if (trimmed === "FAIL") {
      isFailureCase = true;
      continue;
    }

    if ((match = trimmed.match(/^Key = ([0-9a-f]*)$/i))) {
      keyHex = match[1];
      continue;
    }

    if ((match = trimmed.match(/^IV = ([0-9a-f]*)$/i))) {
      ivHex = match[1];
      continue;
    }

    if ((match = trimmed.match(/^CT = ([0-9a-f]*)$/i))) {
      ctHex = match[1];
      continue;
    }

    if (trimmed.startsWith("AAD =")) {
      continue;
    }

    if (!(match = trimmed.match(/^PT = ([0-9a-f]*)$/i))) {
      continue;
    }

    ptHex = match[1];

    if (isFailureCase || ivLen !== 96 || aadLen !== 0) {
      continue;
    }

    if (
      !keyHex ||
      !ivHex ||
      ctHex === null ||
      ptHex === null ||
      ctHex.length === 0 ||
      ptHex.length === 0
    ) {
      continue;
    }

    vectors.push({
      key: hexToBytes(keyHex),
      iv: hexToBytes(ivHex),
      plaintext: hexToBytes(ptHex),
      expectedCiphertext: hexToBytes(ctHex),
    });
  }

  return vectors;
}

test.describe("AES FIPS vectors", () => {
  test("AES-128 GCM matches NIST vectors for KEY + IV + PT = CT", () => {
    const aes = new AESWrapper();
    const vectors = parseGcmEncryptVectors("gcmDecrypt128.rsp");

    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const actualCiphertext = aes.aes128Encrypt(
        vector.key,
        vector.iv,
        vector.plaintext,
      );
      const actualCiphertextHex = bytesToHex(
        actualCiphertext.slice(0, vector.expectedCiphertext.length),
      );

      expect(
        actualCiphertextHex,
        "AES-128 vector did not match expected CT",
      ).toBe(bytesToHex(vector.expectedCiphertext));
    }
  });

  test("AES-256 GCM matches NIST vectors for KEY + IV + PT = CT", () => {
    const aes = new AESWrapper();
    const vectors = parseGcmEncryptVectors("gcmDecrypt256.rsp");

    expect(vectors.length).toBeGreaterThan(0);

    for (const vector of vectors) {
      const actualCiphertext = aes.aes256Encrypt(
        vector.key,
        vector.iv,
        vector.plaintext,
      );
      const actualCiphertextHex = bytesToHex(
        actualCiphertext.slice(0, vector.expectedCiphertext.length),
      );

      expect(
        actualCiphertextHex,
        "AES-256 vector did not match expected CT",
      ).toBe(bytesToHex(vector.expectedCiphertext));
    }
  });
});
