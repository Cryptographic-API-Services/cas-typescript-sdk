import fs from "node:fs";
import path from "node:path";
import { expect } from "@playwright/test";

export type WycheproofResult = "valid" | "invalid" | "acceptable";

export type AeadTest = {
  tcId: number;
  comment: string;
  flags: string[];
  key: string;
  iv: string;
  aad: string;
  msg: string;
  ct: string;
  tag: string;
  result: WycheproofResult;
};

export type AeadTestGroup = {
  ivSize: number;
  keySize: number;
  tagSize: number;
  type: string;
  tests: AeadTest[];
};

export type AeadWithAad = {
  encrypt: (key: number[], nonce: number[], plaintext: number[], aad: number[]) => number[];
  decrypt: (key: number[], nonce: number[], ciphertext: number[], aad: number[]) => number[];
};

// A valid vector must encrypt to ct || tag and decrypt back to msg, an invalid
// one must fail to decrypt, and an acceptable one may go either way.
export function checkAeadVector(cipher: AeadWithAad, vector: AeadTest): void {
  const label = `tcId ${vector.tcId} (${vector.comment})`;
  const key = hexToBytes(vector.key);
  const iv = hexToBytes(vector.iv);
  const aad = hexToBytes(vector.aad);
  const msg = hexToBytes(vector.msg);
  const ctWithTag = [...hexToBytes(vector.ct), ...hexToBytes(vector.tag)];

  if (vector.result === "valid") {
    expect(
      bytesToHex(cipher.encrypt(key, iv, msg, aad)),
      `${label}: ciphertext||tag mismatch`,
    ).toBe(vector.ct + vector.tag);
    expect(
      bytesToHex(cipher.decrypt(key, iv, ctWithTag, aad)),
      `${label}: plaintext mismatch`,
    ).toBe(vector.msg);
  } else if (vector.result === "invalid") {
    expect(
      () => cipher.decrypt(key, iv, ctWithTag, aad),
      `${label}: decrypt accepted an invalid vector`,
    ).toThrow();
  } else {
    try {
      cipher.decrypt(key, iv, ctWithTag, aad);
    } catch {
      // Acceptable vectors may be rejected.
    }
  }
}

export type EddsaTest = {
  tcId: number;
  comment: string;
  flags: string[];
  msg: string;
  sig: string;
  result: WycheproofResult;
};

export type EddsaTestGroup = {
  publicKey: {
    curve: string;
    pk: string;
  };
  tests: EddsaTest[];
};

export type LegacyEddsaTestGroup = {
  key: {
    pk: string;
    sk: string;
  };
};

export type XdhTest = {
  tcId: number;
  comment: string;
  flags: string[];
  public: string;
  private: string;
  shared: string;
  result: WycheproofResult;
};

export type XdhTestGroup = {
  curve: string;
  tests: XdhTest[];
};

export type MacTest = {
  tcId: number;
  comment: string;
  flags: string[];
  key: string;
  msg: string;
  tag: string;
  result: WycheproofResult;
};

export type MacTestGroup = {
  keySize: number;
  tagSize: number;
  tests: MacTest[];
};

export type HkdfTest = {
  tcId: number;
  comment: string;
  flags: string[];
  ikm: string;
  salt: string;
  info: string;
  size: number;
  okm: string;
  result: WycheproofResult;
};

export type HkdfTestGroup = {
  keySize: number;
  tests: HkdfTest[];
};

export type SignatureTest = {
  tcId: number;
  comment: string;
  flags: string[];
  msg: string;
  sig: string;
  result: WycheproofResult;
};

export type RsaSignatureTestGroup = {
  type: string;
  keySize: number;
  sha: string;
  mgfSha?: string;
  sLen?: number;
  publicKeyPem: string;
  tests: SignatureTest[];
};

export type KeywrapTest = {
  tcId: number;
  comment: string;
  flags: string[];
  key: string;
  msg: string;
  ct: string;
  result: WycheproofResult;
};

export type KeywrapTestGroup = {
  keySize: number;
  tests: KeywrapTest[];
};

export type WycheproofFile<TGroup> = {
  algorithm: string;
  numberOfTests: number;
  testGroups: TGroup[];
};

export function loadWycheproof<TGroup>(fileName: string): WycheproofFile<TGroup> {
  const filePath = path.join(__dirname, "..", "data", "wycheproof", fileName);
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Missing Wycheproof vector file ${fileName}; run \`npm run wycheproof:fetch\` first.`,
    );
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function hexToBytes(hex: string): number[] {
  if (!hex) {
    return [];
  }

  return Array.from(Buffer.from(hex, "hex"));
}

export function bytesToHex(bytes: number[]): string {
  return Buffer.from(bytes).toString("hex");
}
