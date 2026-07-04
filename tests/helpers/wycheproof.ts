import fs from "node:fs";
import path from "node:path";

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

export type WycheproofFile<TGroup> = {
  algorithm: string;
  numberOfTests: number;
  testGroups: TGroup[];
};

export function loadWycheproof<TGroup>(fileName: string): WycheproofFile<TGroup> {
  const filePath = path.join(__dirname, "..", "data", "wycheproof", fileName);
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
