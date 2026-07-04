import { expect, test } from "@playwright/test";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import {
  AeadTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

// The SDK's AES-GCM API takes a 96-bit nonce, appends the 128-bit tag to the
// ciphertext, and has no AAD parameter — so only vectors matching those
// constraints are usable here.
function usableGroups(keySize: number): AeadTestGroup[] {
  const file = loadWycheproof<AeadTestGroup>("aes_gcm_test.json");
  return file.testGroups.filter(
    (group) =>
      group.ivSize === 96 && group.tagSize === 128 && group.keySize === keySize,
  );
}

test.describe("Wycheproof AES-GCM vectors", () => {
  for (const keySize of [128, 256]) {
    test(`AES-${keySize} GCM encrypt/decrypt matches Wycheproof vectors`, () => {
      const aes = new AESWrapper();
      const encrypt =
        keySize === 128
          ? aes.aes128Encrypt.bind(aes)
          : aes.aes256Encrypt.bind(aes);
      const decrypt =
        keySize === 128
          ? aes.aes128Decrypt.bind(aes)
          : aes.aes256Decrypt.bind(aes);

      let vectorsRun = 0;

      for (const group of usableGroups(keySize)) {
        for (const vector of group.tests) {
          if (vector.aad !== "") {
            continue;
          }

          const label = `tcId ${vector.tcId} (${vector.comment})`;
          const key = hexToBytes(vector.key);
          const iv = hexToBytes(vector.iv);
          const msg = hexToBytes(vector.msg);
          const ctWithTag = [...hexToBytes(vector.ct), ...hexToBytes(vector.tag)];
          vectorsRun++;

          if (vector.result === "valid") {
            const ciphertext = encrypt(key, iv, msg);
            expect(
              bytesToHex(ciphertext),
              `${label}: ciphertext||tag mismatch`,
            ).toBe(vector.ct + vector.tag);

            const plaintext = decrypt(key, iv, ctWithTag);
            expect(bytesToHex(plaintext), `${label}: plaintext mismatch`).toBe(
              vector.msg,
            );
          } else {
            expect(
              () => decrypt(key, iv, ctWithTag),
              `${label}: decrypt accepted an invalid ciphertext/tag`,
            ).toThrow();
          }
        }
      }

      expect(vectorsRun, "no usable vectors found").toBeGreaterThan(0);
    });
  }
});
