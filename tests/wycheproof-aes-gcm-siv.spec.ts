import { expect, test } from "@playwright/test";
import { AESGCMSIVWrapper } from "../src-ts/symmetric/aes-gcm-siv-wrapper";
import {
  AeadTestGroup,
  AeadWithAad,
  checkAeadVector,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof AES-GCM-SIV vectors", () => {
  test("AES-128/256-GCM-SIV with AAD matches every Wycheproof vector", () => {
    const siv = new AESGCMSIVWrapper();
    const ciphers: Record<number, AeadWithAad> = {
      128: {
        encrypt: (k, n, p, a) => siv.aes128EncryptWithAad(k, n, p, a),
        decrypt: (k, n, c, a) => siv.aes128DecryptWithAad(k, n, c, a),
      },
      256: {
        encrypt: (k, n, p, a) => siv.aes256EncryptWithAad(k, n, p, a),
        decrypt: (k, n, c, a) => siv.aes256DecryptWithAad(k, n, c, a),
      },
    };
    const file = loadWycheproof<AeadTestGroup>("aes_gcm_siv_test.json");

    let vectorsRun = 0;
    for (const group of file.testGroups) {
      for (const vector of group.tests) {
        vectorsRun++;
        checkAeadVector(ciphers[group.keySize], vector);
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
