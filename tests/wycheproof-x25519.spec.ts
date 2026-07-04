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

    for (const group of file.testGroups) {
      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const secretKey = hexToBytes(vector.private);
        const publicKey = hexToBytes(vector.public);
        vectorsRun++;

        // x25519-dalek clamps the private key and masks the public key's high
        // bit per RFC 7748, so both "valid" and "acceptable" vectors (twist
        // points, low-order points yielding an all-zero shared secret, etc.)
        // must produce the expected shared secret.
        const shared = x25519.generateSharedSecret(secretKey, publicKey);
        expect(bytesToHex(shared), `${label}: shared secret mismatch`).toBe(
          vector.shared,
        );
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
