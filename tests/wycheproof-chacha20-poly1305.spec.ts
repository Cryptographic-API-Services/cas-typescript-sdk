import { expect, test } from "@playwright/test";
import { ChaCha20Poly1305Wrapper } from "../src-ts/symmetric/chacha20poly1305-wrapper";
import {
  AeadTestGroup,
  AeadWithAad,
  checkAeadVector,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof ChaCha20-Poly1305 vectors", () => {
  test("ChaCha20-Poly1305 with AAD matches every Wycheproof vector", () => {
    const chacha = new ChaCha20Poly1305Wrapper();
    const cipher: AeadWithAad = {
      encrypt: (k, n, p, a) => chacha.encryptWithAad(k, n, p, a),
      decrypt: (k, n, c, a) => chacha.decryptWithAad(k, n, c, a),
    };
    const file = loadWycheproof<AeadTestGroup>("chacha20_poly1305_test.json");

    let vectorsRun = 0;
    for (const group of file.testGroups) {
      for (const vector of group.tests) {
        vectorsRun++;
        checkAeadVector(cipher, vector);
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
