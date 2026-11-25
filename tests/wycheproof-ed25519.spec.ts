import { expect, test } from "@playwright/test";
import { Ed25519Wrapper } from "../src-ts/signature/ed25519-wrapper";
import {
  EddsaTestGroup,
  hexToBytes,
  LegacyEddsaTestGroup,
  loadWycheproof,
} from "./helpers/wycheproof";

// Malformed signatures (e.g. wrong length) may throw instead of returning
// false — both count as a rejection.
function verifies(verify: () => boolean): boolean {
  try {
    return verify();
  } catch {
    return false;
  }
}

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

        const verified = verifies(() => ed25519.verifyBytes(publicKey, message, signature));

        // "acceptable" vectors (e.g. small- or mixed-order public keys) may
        // be accepted or rejected, so only valid/invalid are asserted.
        if (vector.result === "valid") {
          expect(verified, `${label}: valid signature was rejected`).toBe(true);
        } else if (vector.result === "invalid") {
          expect(verified, `${label}: invalid signature was accepted`).toBe(
            false,
          );
        }
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });

  test("verifying with the key pair agrees with verifying with the public key", () => {
    const ed25519 = new Ed25519Wrapper();
    const file = loadWycheproof<EddsaTestGroup>("ed25519_test.json");
    const legacy = loadWycheproof<LegacyEddsaTestGroup>("eddsa_test.json");
    const secretKeys = new Map(
      legacy.testGroups.map((group) => [group.key.pk, hexToBytes(group.key.sk)]),
    );

    let vectorsRun = 0;
    let malleabilityVectorsRun = 0;

    for (const group of file.testGroups) {
      const secretKey = secretKeys.get(group.publicKey.pk);
      if (!secretKey) {
        continue;
      }
      const publicKey = hexToBytes(group.publicKey.pk);

      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const message = hexToBytes(vector.msg);
        const signature = hexToBytes(vector.sig);
        vectorsRun++;
        if (vector.flags.includes("SignatureMalleability")) {
          malleabilityVectorsRun++;
        }

        const withKeyPair = verifies(() =>
          ed25519.verifyWithKeyPairBytes(secretKey, message, signature),
        );
        const withPublicKey = verifies(() =>
          ed25519.verifyBytes(publicKey, message, signature),
        );

        expect(withKeyPair, `${label}: key pair and public key verification disagree`).toBe(
          withPublicKey,
        );
        if (vector.result === "valid") {
          expect(withKeyPair, `${label}: valid signature was rejected`).toBe(true);
        } else if (vector.result === "invalid") {
          expect(withKeyPair, `${label}: invalid signature was accepted`).toBe(false);
        }
      }
    }

    expect(vectorsRun).toBeGreaterThan(0);
    expect(malleabilityVectorsRun).toBeGreaterThan(0);
  });
});
