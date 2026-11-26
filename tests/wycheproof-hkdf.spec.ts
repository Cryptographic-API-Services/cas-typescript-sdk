import { expect, test } from "@playwright/test";
import { HkdfWrapper } from "../src-ts/kdf/hkdf";
import { HkdfTestGroup, bytesToHex, hexToBytes, loadWycheproof } from "./helpers/wycheproof";

type Extract = (salt: number[], ikm: number[]) => number[];
type Expand = (prk: number[], info: number[], length: number) => number[];
type Derive = (salt: number[], ikm: number[], info: number[], length: number) => number[];

const hkdf = new HkdfWrapper();

const suites: { name: string; fileName: string; extract: Extract; expand: Expand; derive: Derive }[] = [
  {
    name: "HKDF-SHA256",
    fileName: "hkdf_sha256_test.json",
    extract: hkdf.hkdfSha256Extract.bind(hkdf),
    expand: hkdf.hkdfSha256Expand.bind(hkdf),
    derive: hkdf.hkdfSha256Derive.bind(hkdf),
  },
  {
    name: "HKDF-SHA512",
    fileName: "hkdf_sha512_test.json",
    extract: hkdf.hkdfSha512Extract.bind(hkdf),
    expand: hkdf.hkdfSha512Expand.bind(hkdf),
    derive: hkdf.hkdfSha512Derive.bind(hkdf),
  },
];

for (const suite of suites) {
  test.describe(`Wycheproof ${suite.name} vectors`, () => {
    test("derive, and extract + expand, match Wycheproof expectations", () => {
      const file = loadWycheproof<HkdfTestGroup>(suite.fileName);
      let vectorsRun = 0;
      let invalidRun = 0;

      for (const group of file.testGroups) {
        for (const vector of group.tests) {
          const label = `tcId ${vector.tcId} (${vector.comment})`;
          const ikm = hexToBytes(vector.ikm);
          const salt = hexToBytes(vector.salt);
          const info = hexToBytes(vector.info);
          vectorsRun++;

          if (vector.result === "valid") {
            expect(bytesToHex(suite.derive(salt, ikm, info, vector.size)), `${label}: derive`).toBe(vector.okm);
            const prk = suite.extract(salt, ikm);
            expect(bytesToHex(suite.expand(prk, info, vector.size)), `${label}: extract + expand`).toBe(vector.okm);
          } else {
            // Every invalid case is an output size above 255 * HashLen.
            invalidRun++;
            expect(() => suite.derive(salt, ikm, info, vector.size), `${label}: derive`).toThrow();
            expect(() => suite.expand(suite.extract(salt, ikm), info, vector.size), `${label}: expand`).toThrow();
          }
        }
      }

      expect(vectorsRun).toBe(file.numberOfTests);
      expect(invalidRun).toBeGreaterThan(0);
    });
  });
}
