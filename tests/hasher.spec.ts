import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { sha256, sha512 } from "../index";
import { Blake2Wrapper, SHAWrapper } from "../src-ts/hashers/index";

type Sha3Vector = {
  lengthBits: number;
  message: number[];
  digest: number[];
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

function parseSha3Vectors(fileName: string): Sha3Vector[] {
  const filePath = path.join(__dirname, "data", "hashers", fileName);
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const vectors: Sha3Vector[] = [];

  let lengthBits: number | null = null;
  let messageHex: string | null = null;

  for (const line of lines) {
    const trimmed = line.trim();
    let match: RegExpMatchArray | null = null;

    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) {
      continue;
    }

    if ((match = trimmed.match(/^Len = (\d+)$/))) {
      lengthBits = Number(match[1]);
      messageHex = null;
      continue;
    }

    if ((match = trimmed.match(/^Msg = ([0-9a-f]*)$/i))) {
      messageHex = match[1];
      continue;
    }

    if (!(match = trimmed.match(/^MD = ([0-9a-f]+)$/i))) {
      continue;
    }

    if (lengthBits === null || messageHex === null) {
      continue;
    }

    const message =
      lengthBits === 0 ? [] : hexToBytes(messageHex).slice(0, lengthBits / 8);

    vectors.push({
      lengthBits,
      message,
      digest: hexToBytes(match[1]),
    });
  }

  return vectors;
}

test.describe("SHA512 Tests", () => {
  test("hash", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });
});

test.describe("SHA256 Tests", () => {
  test("hash", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify256(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new SHAWrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash256(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify256(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });
});

test.describe("SHA3 NIST vectors", () => {
  const sha3_256_files = [
    "SHA3_256ShortMsg.rsp",
    "SHA3_256LongMsg.rsp",
  ];
  const sha3_512_files = [
    "SHA3_512ShortMsg.rsp",
    "SHA3_512LongMsg.rsp",
  ];

  for (const fileName of sha3_256_files) {
    test(`SHA3-256 matches ${fileName}`, () => {
      const vectors = parseSha3Vectors(fileName);
      expect(vectors.length).toBeGreaterThan(0);

      for (const vector of vectors) {
        expect(
          bytesToHex(sha256(vector.message)),
          `SHA3-256 mismatch in ${fileName} at Len=${vector.lengthBits}`,
        ).toBe(bytesToHex(vector.digest));
      }
    });
  }

  for (const fileName of sha3_512_files) {
    test(`SHA3-512 matches ${fileName}`, () => {
      const vectors = parseSha3Vectors(fileName);
      expect(vectors.length).toBeGreaterThan(0);

      for (const vector of vectors) {
        expect(
          bytesToHex(sha512(vector.message)),
          `SHA3-512 mismatch in ${fileName} at Len=${vector.lengthBits}`,
        ).toBe(bytesToHex(vector.digest));
      }
    });
  }
});

test.describe("Blake2 512", () => {
  test("hash", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    expect(hashed).not.toEqual(tohashBytes);
  });

  test("verify pass", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(true);
  });

  test("verify fail", () => {
    const wrapper = new Blake2Wrapper();
    const tohashed: string = "This is my array to hash";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const hashed = wrapper.hash512(tohashBytes);
    const toVerify = "This Is Not The Same";
    const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
    const verified = wrapper.verify512(hashed, toVerifyBytes);
    expect(verified).toBe(false);
  });

  test.describe("Blake2 256", () => {
    test("hash", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      expect(hashed).not.toEqual(tohashBytes);
    });

    test("verify pass", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      expect(verified).toBe(true);
    });

    test("verify fail", () => {
      const wrapper = new Blake2Wrapper();
      const tohashed: string = "This is my array to hash";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const hashed = wrapper.hash256(tohashBytes);
      const toVerify = "This Is Not The Same";
      const toVerifyBytes: Array<number> = Array.from(encoder.encode(toVerify));
      const verified = wrapper.verify256(hashed, toVerifyBytes);
      expect(verified).toBe(false);
    });
  });
});
