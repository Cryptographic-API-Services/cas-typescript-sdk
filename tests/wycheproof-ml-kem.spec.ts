import { expect, test } from "@playwright/test";
import { MlKem1024Wrapper } from "../src-ts/pqc/ml-kem-wrapper";
import { bytesToHex, hexToBytes, loadWycheproof } from "./helpers/wycheproof";

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
    const file = loadWycheproof<MlKemDecapsTestGroup>(
      "mlkem_1024_semi_expanded_decaps_test.json",
    );

    let vectorsRun = 0;

    for (const group of file.testGroups) {
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
