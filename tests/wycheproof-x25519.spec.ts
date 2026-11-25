import { expect, test } from "@playwright/test";
import { X25519Wrapper } from "../src-ts/key_exchange/x25519";
import {
  XdhTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof X25519 vectors", () => {
  test("shared secret computation matches Wycheproof expectations", () => {
    const x25519 = new X25519Wrapper();
    const file = loadWycheproof<XdhTestGroup>("x25519_test.json");

    let vectorsRun = 0;
    let lowOrderRejected = 0;

    for (const group of file.testGroups) {
      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const secretKey = hexToBytes(vector.private);
        const publicKey = hexToBytes(vector.public);
        vectorsRun++;

        // Low-order public keys force the all-zero shared secret whatever the
        // private key is, so they must be rejected.
        if (
          vector.flags.includes("ZeroSharedSecret") ||
          vector.flags.includes("LowOrderPublic")
        ) {
          expect(
            () => x25519.generateSharedSecret(secretKey, publicKey),
            `${label}: low-order public key must be rejected`,
          ).toThrow();
          lowOrderRejected++;
          continue;
        }

        if (vector.result === "valid") {
          const shared = x25519.generateSharedSecret(secretKey, publicKey);
          expect(bytesToHex(shared), `${label}: shared secret mismatch`).toBe(
            vector.shared,
          );
          continue;
        }

        // Other "acceptable" vectors (twist points, non-canonical public keys)
        // may go either way, but a returned secret must still be correct.
        let shared: Array<number> | undefined;
        try {
          shared = x25519.generateSharedSecret(secretKey, publicKey);
        } catch {
          continue;
        }
        expect(bytesToHex(shared), `${label}: shared secret mismatch`).toBe(
          vector.shared,
        );
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
    expect(lowOrderRejected).toBeGreaterThan(0);
  });
});
