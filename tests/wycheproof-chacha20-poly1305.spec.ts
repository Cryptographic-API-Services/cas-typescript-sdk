import { expect, test } from "@playwright/test";
import { ChaCha20Poly1305Wrapper } from "../src-ts/symmetric/chacha20poly1305-wrapper";
import {
  AeadTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof ChaCha20-Poly1305 vectors", () => {
  test("encrypt/decrypt matches Wycheproof vectors", () => {
    const chacha = new ChaCha20Poly1305Wrapper();
    const file = loadWycheproof<AeadTestGroup>("chacha20_poly1305_test.json");

    // The SDK's API takes a 96-bit nonce, appends the 128-bit tag to the
    // ciphertext, and has no AAD parameter. All of Wycheproof's "invalid"
    // ChaCha20-Poly1305 vectors carry AAD, so rejection is instead checked by
    // corrupting the tag of each valid vector.
    const groups = file.testGroups.filter(
      (group) =>
        group.ivSize === 96 && group.tagSize === 128 && group.keySize === 256,
    );

    let vectorsRun = 0;

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

        const ciphertext = chacha.encrypt(key, iv, msg);
        expect(bytesToHex(ciphertext), `${label}: ciphertext||tag mismatch`).toBe(
          vector.ct + vector.tag,
        );

        const plaintext = chacha.decrypt(key, iv, ctWithTag);
        expect(bytesToHex(plaintext), `${label}: plaintext mismatch`).toBe(
          vector.msg,
        );

        const corrupted = [...ctWithTag];
        corrupted[corrupted.length - 1] ^= 0x01;
        expect(
          () => chacha.decrypt(key, iv, corrupted),
          `${label}: decrypt accepted a corrupted tag`,
        ).toThrow();
      }
    }

    expect(vectorsRun, "no usable vectors found").toBeGreaterThan(0);
  });
});
