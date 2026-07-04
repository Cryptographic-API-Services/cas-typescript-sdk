import { expect, test } from "@playwright/test";
import { Ed25519Wrapper } from "../src-ts/signature/ed25519-wrapper";
import {
  EddsaTestGroup,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof Ed25519 vectors", () => {
  test("signature verification matches Wycheproof expectations", () => {
    const ed25519 = new Ed25519Wrapper();
    const file = loadWycheproof<EddsaTestGroup>("ed25519_test.json");

    let vectorsRun = 0;

    for (const group of file.testGroups) {
      const publicKey = hexToBytes(group.publicKey.pk);

      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const message = hexToBytes(vector.msg);
        const signature = hexToBytes(vector.sig);
        vectorsRun++;

        // Malformed signatures (e.g. wrong length) may throw instead of
        // returning false — both count as a rejection.
        let verified = false;
        try {
          verified = ed25519.verifyBytes(publicKey, message, signature);
        } catch {
          verified = false;
        }

        if (vector.result === "valid") {
          expect(verified, `${label}: valid signature was rejected`).toBe(true);
        } else {
          expect(verified, `${label}: invalid signature was accepted`).toBe(
            false,
          );
        }
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
