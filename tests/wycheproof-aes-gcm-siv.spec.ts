import { expect, test } from "@playwright/test";
import { AESGCMSIVWrapper } from "../src-ts/symmetric/aes-gcm-siv-wrapper";
import {
  AeadTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof AES-GCM-SIV vectors", () => {
  for (const keySize of [128, 256]) {
    test(`AES-${keySize} GCM-SIV encrypt/decrypt matches Wycheproof vectors`, () => {
      const aes = new AESGCMSIVWrapper();
      const encrypt =
        keySize === 128
          ? aes.aes128Encrypt.bind(aes)
          : aes.aes256Encrypt.bind(aes);
      const decrypt =
        keySize === 128
          ? aes.aes128Decrypt.bind(aes)
          : aes.aes256Decrypt.bind(aes);

      const file = loadWycheproof<AeadTestGroup>("aes_gcm_siv_test.json");
      const groups = file.testGroups.filter(
        (group) =>
          group.ivSize === 96 &&
          group.tagSize === 128 &&
          group.keySize === keySize,
      );

      let vectorsRun = 0;

      // All of Wycheproof's "invalid" AES-GCM-SIV vectors carry AAD (which the
      // SDK's API does not accept), so rejection is instead checked by
      // corrupting the tag of each valid vector.
      for (const group of groups) {
        for (const vector of group.tests) {
          if (vector.aad !== "" || vector.result !== "valid") {
            continue;
          }

          const label = `tcId ${vector.tcId} (${vector.comment})`;
          const key = hexToBytes(vector.key);
          const iv = hexToBytes(vector.iv);
          const msg = hexToBytes(vector.msg);
          const ctWithTag = [...hexToBytes(vector.ct), ...hexToBytes(vector.tag)];
          vectorsRun++;

          const ciphertext = encrypt(key, iv, msg);
          expect(
            bytesToHex(ciphertext),
            `${label}: ciphertext||tag mismatch`,
          ).toBe(vector.ct + vector.tag);

          const plaintext = decrypt(key, iv, ctWithTag);
          expect(bytesToHex(plaintext), `${label}: plaintext mismatch`).toBe(
            vector.msg,
          );

          const corrupted = [...ctWithTag];
          corrupted[corrupted.length - 1] ^= 0x01;
          expect(
            () => decrypt(key, iv, corrupted),
            `${label}: decrypt accepted a corrupted tag`,
          ).toThrow();
        }
      }

      expect(vectorsRun, "no usable vectors found").toBeGreaterThan(0);
    });
  }
});
