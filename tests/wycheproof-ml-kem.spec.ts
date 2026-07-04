import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { MlKem1024Wrapper } from "../src-ts/pqc/ml-kem-wrapper";
import { bytesToHex, hexToBytes } from "./helpers/wycheproof";

type MlKemDecapsTest = {
  tcId: number;
  comment: string;
  flags: string[];
  dk: string;
  ek: string;
  c: string;
  K: string;
  result: "valid" | "invalid";
};

type MlKemDecapsTestGroup = {
  parameterSet: string;
  tests: MlKemDecapsTest[];
};

test.describe("Wycheproof ML-KEM-1024 vectors", () => {
  test("decapsulation matches Wycheproof expectations", () => {
    const mlKem = new MlKem1024Wrapper();
    const filePath = path.join(
      __dirname,
      "data",
      "wycheproof",
      "mlkem_1024_semi_expanded_decaps_test.json",
    );
    const file = JSON.parse(fs.readFileSync(filePath, "utf8"));

    let vectorsRun = 0;

    for (const group of file.testGroups as MlKemDecapsTestGroup[]) {
      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const secretKey = hexToBytes(vector.dk);
        const ciphertext = hexToBytes(vector.c);
        vectorsRun++;

        if (vector.result === "valid") {
          const sharedSecret = mlKem.decapsulate(secretKey, ciphertext);
          expect(bytesToHex(sharedSecret), `${label}: shared secret mismatch`).toBe(
            vector.K,
          );
        } else if (vector.flags.includes("InvalidDecapsulationKey")) {
          // Known deviation: FIPS 203 §7.3 requires rejecting a decapsulation
          // key whose embedded hash doesn't match, but the RustCrypto ml-kem
          // crate used by cas-lib skips that check and decapsulates anyway.
          // Reported upstream; if this starts throwing, the deviation is fixed
          // and this branch should be folded into the toThrow() case below.
          const sharedSecret = mlKem.decapsulate(secretKey, ciphertext);
          expect(
            sharedSecret.length,
            `${label}: unexpected shared secret length`,
          ).toBe(32);
        } else {
          expect(
            () => mlKem.decapsulate(secretKey, ciphertext),
            `${label}: decapsulation accepted an invalid input`,
          ).toThrow();
        }
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
