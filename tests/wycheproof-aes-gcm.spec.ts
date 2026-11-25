import { expect, test } from "@playwright/test";
import { CasErrorCode, isCasError } from "../src-ts/errors";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import {
  AeadTest,
  AeadTestGroup,
  AeadWithAad,
  checkAeadVector,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

function expectInvalidNonce(fn: () => unknown, label: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (err) {
    caught = err;
  }
  expect(isCasError(caught, CasErrorCode.InvalidNonce), `${label}: expected CAS_INVALID_NONCE`).toBe(true);
}

// The SDK has no AES-192, and cas-lib's AES-GCM only takes a 96-bit nonce, so a
// valid vector with any other nonce size has no expected output to check. Those
// are counted by reason (pinned below so none is dropped silently), and the
// nonce-size ones must still be rejected with CAS_INVALID_NONCE.
function unsupportedReason(group: AeadTestGroup, vector: AeadTest): string | undefined {
  if (group.keySize === 192) {
    return "aes192";
  }
  if (group.ivSize !== 96 && vector.result === "valid") {
    return "nonceSize";
  }
  return undefined;
}

test.describe("Wycheproof AES-GCM vectors", () => {
  test("AES-128/256-GCM with AAD matches every Wycheproof vector", () => {
    const aes = new AESWrapper();
    const ciphers: Record<number, AeadWithAad> = {
      128: {
        encrypt: (k, n, p, a) => aes.aes128EncryptWithAad(k, n, p, a),
        decrypt: (k, n, c, a) => aes.aes128DecryptWithAad(k, n, c, a),
      },
      256: {
        encrypt: (k, n, p, a) => aes.aes256EncryptWithAad(k, n, p, a),
        decrypt: (k, n, c, a) => aes.aes256DecryptWithAad(k, n, c, a),
      },
    };
    const file = loadWycheproof<AeadTestGroup>("aes_gcm_test.json");

    let vectorsRun = 0;
    const skipped: Record<string, number> = {};

    for (const group of file.testGroups) {
      for (const vector of group.tests) {
        const reason = unsupportedReason(group, vector);
        if (reason) {
          skipped[reason] = (skipped[reason] ?? 0) + 1;
          if (reason === "nonceSize") {
            const cipher = ciphers[group.keySize];
            const label = `tcId ${vector.tcId} (${vector.comment})`;
            const key = hexToBytes(vector.key);
            const iv = hexToBytes(vector.iv);
            const aad = hexToBytes(vector.aad);
            expectInvalidNonce(() => cipher.encrypt(key, iv, hexToBytes(vector.msg), aad), label);
            expectInvalidNonce(
              () => cipher.decrypt(key, iv, [...hexToBytes(vector.ct), ...hexToBytes(vector.tag)], aad),
              label,
            );
          }
          continue;
        }
        vectorsRun++;
        checkAeadVector(ciphers[group.keySize], vector);
      }
    }

    expect(skipped).toEqual({ aes192: 103, nonceSize: 76 });
    expect(vectorsRun + 179).toBe(file.numberOfTests);
  });
});
