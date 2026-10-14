import fs from "node:fs";
import path from "node:path";
import { test, expect } from "@playwright/test";
import { sha256, sha2Hash256, sha2Hash512, sha512 } from "../index";
import {
  Blake2Wrapper,
  HasherFactory,
  HasherType,
  SHA2Wrapper,
  SHAWrapper,
} from "../src-ts/hashers/index";

type ShaVector = {
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

function parseShaVectors(fileName: string): ShaVector[] {
  const filePath = path.join(__dirname, "data", "hashers", fileName);
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  const vectors: ShaVector[] = [];

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
      const vectors = parseShaVectors(fileName);
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
      const vectors = parseShaVectors(fileName);
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

test.describe("SHA2 Tests", () => {
  const encoder = new TextEncoder();
  const tohashBytes: Array<number> = Array.from(
    encoder.encode("This is my array to hash"),
  );
  const otherBytes: Array<number> = Array.from(
    encoder.encode("This Is Not The Same"),
  );

  test("hash512 produces a 64-byte digest", () => {
    const hashed = new SHA2Wrapper().hash512(tohashBytes);
    expect(hashed.length).toBe(64);
  });

  test("hash256 produces a 32-byte digest", () => {
    const hashed = new SHA2Wrapper().hash256(tohashBytes);
    expect(hashed.length).toBe(32);
  });

  test("FIPS 180-4 \"abc\" examples", () => {
    const wrapper = new SHA2Wrapper();
    const abc = Array.from(encoder.encode("abc"));
    expect(bytesToHex(wrapper.hash256(abc))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(bytesToHex(wrapper.hash512(abc))).toBe(
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" +
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
  });

  test("differs from SHA3 for the same input", () => {
    const sha2 = new SHA2Wrapper();
    const sha3 = new SHAWrapper();
    expect(sha2.hash256(tohashBytes)).not.toEqual(sha3.hash256(tohashBytes));
    expect(sha2.hash512(tohashBytes)).not.toEqual(sha3.hash512(tohashBytes));
  });

  test("verify pass", () => {
    const wrapper = new SHA2Wrapper();
    expect(wrapper.verify512(wrapper.hash512(tohashBytes), tohashBytes)).toBe(true);
    expect(wrapper.verify256(wrapper.hash256(tohashBytes), tohashBytes)).toBe(true);
  });

  test("verify fail on different data", () => {
    const wrapper = new SHA2Wrapper();
    expect(wrapper.verify512(wrapper.hash512(tohashBytes), otherBytes)).toBe(false);
    expect(wrapper.verify256(wrapper.hash256(tohashBytes), otherBytes)).toBe(false);
  });

  test("verify fail on a single flipped digest bit", () => {
    const wrapper = new SHA2Wrapper();
    const digest512 = wrapper.hash512(tohashBytes);
    const digest256 = wrapper.hash256(tohashBytes);
    digest512[0] ^= 0x01;
    digest256[digest256.length - 1] ^= 0x80;
    expect(wrapper.verify512(digest512, tohashBytes)).toBe(false);
    expect(wrapper.verify256(digest256, tohashBytes)).toBe(false);
  });

  test("verify fail on a truncated digest", () => {
    const wrapper = new SHA2Wrapper();
    expect(
      wrapper.verify512(wrapper.hash512(tohashBytes).slice(0, 32), tohashBytes),
    ).toBe(false);
    expect(
      wrapper.verify256(wrapper.hash256(tohashBytes).slice(0, 16), tohashBytes),
    ).toBe(false);
  });

  test("rejects empty input", () => {
    const wrapper = new SHA2Wrapper();
    expect(() => wrapper.hash512([])).toThrow();
    expect(() => wrapper.hash256([])).toThrow();
    expect(() => wrapper.verify512([], tohashBytes)).toThrow();
    expect(() => wrapper.verify256(wrapper.hash256(tohashBytes), [])).toThrow();
  });

  test("HasherFactory returns a SHA2Wrapper for HasherType.SHA2", () => {
    const hasher = new HasherFactory().getHasher(HasherType.SHA2);
    expect(hasher).toBeInstanceOf(SHA2Wrapper);
    expect(hasher.hash256(tohashBytes)).toEqual(
      new SHA2Wrapper().hash256(tohashBytes),
    );
  });
});

test.describe("SHA2 NIST vectors", () => {
  const sha2_256_files = ["SHA256ShortMsg.rsp", "SHA256LongMsg.rsp"];
  const sha2_512_files = ["SHA512ShortMsg.rsp", "SHA512LongMsg.rsp"];

  const suites = [
    { name: "SHA2-256", files: sha2_256_files, digestBytes: 32, wrapperHash: "hash256", wrapperVerify: "verify256", ffiHash: sha2Hash256 },
    { name: "SHA2-512", files: sha2_512_files, digestBytes: 64, wrapperHash: "hash512", wrapperVerify: "verify512", ffiHash: sha2Hash512 },
  ] as const;

  for (const suite of suites) {
    for (const fileName of suite.files) {
      test(`${suite.name} matches ${fileName}`, () => {
        const wrapper = new SHA2Wrapper();
        const vectors = parseShaVectors(fileName);
        expect(vectors.length).toBeGreaterThan(0);

        for (const vector of vectors) {
          const label = `${suite.name} mismatch in ${fileName} at Len=${vector.lengthBits}`;
          expect(vector.digest.length, label).toBe(suite.digestBytes);

          // The wrapper rejects empty input up front, so the Len = 0 vector
          // goes through the FFI function the wrapper delegates to.
          if (vector.message.length === 0) {
            expect(bytesToHex(suite.ffiHash(vector.message)), label).toBe(
              bytesToHex(vector.digest),
            );
            continue;
          }

          expect(bytesToHex(wrapper[suite.wrapperHash](vector.message)), label).toBe(
            bytesToHex(vector.digest),
          );
          expect(
            wrapper[suite.wrapperVerify](vector.digest, vector.message),
            `${label}: verify rejected the NIST digest`,
          ).toBe(true);
        }
      });
    }
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
