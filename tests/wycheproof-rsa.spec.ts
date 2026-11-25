import { expect, test } from "@playwright/test";
import { createPublicKey } from "node:crypto";
import { verifyRsa, verifyRsaPss } from "../index";
import { RSAWrapper } from "../src-ts/asymmetric/RSAWrapper";
import { hexToBytes, loadWycheproof, RsaSignatureTestGroup } from "./helpers/wycheproof";

type Verify = (publicKey: string, message: number[], signature: number[]) => boolean;

// Malformed signatures (e.g. wrong length) may throw instead of returning
// false — both count as a rejection.
function verifies(verify: () => boolean): boolean {
  try {
    return verify();
  } catch {
    return false;
  }
}

// The vectors carry SPKI public keys; RSAWrapper takes PKCS#1 PEM.
function toPkcs1Pem(spkiPem: string): string {
  return createPublicKey(spkiPem).export({ type: "pkcs1", format: "pem" }).toString();
}

// The wrapper rejects empty messages before reaching the native binding, so
// empty-message vectors are checked against the binding directly.
function runVectors(fileName: string, wrapperVerify: Verify, bindingVerify: Verify) {
  const file = loadWycheproof<RsaSignatureTestGroup>(fileName);
  let vectorsRun = 0;

  for (const group of file.testGroups) {
    const publicKey = toPkcs1Pem(group.publicKeyPem);

    for (const vector of group.tests) {
      const label = `tcId ${vector.tcId} (${vector.comment})`;
      const message = hexToBytes(vector.msg);
      const signature = hexToBytes(vector.sig);
      const verify = message.length === 0 ? bindingVerify : wrapperVerify;
      vectorsRun++;

      const verified = verifies(() => verify(publicKey, message, signature));

      // "acceptable" vectors (e.g. a DigestInfo missing its NULL parameter)
      // may be accepted or rejected, so only valid/invalid are asserted.
      if (vector.result === "valid") {
        expect(verified, `${label}: valid signature was rejected`).toBe(true);
      } else if (vector.result === "invalid") {
        expect(verified, `${label}: invalid signature was accepted`).toBe(false);
      }
    }
  }

  expect(vectorsRun).toBe(file.numberOfTests);
}

test.describe("Wycheproof RSA signature vectors", () => {
  test("RSASSA-PSS SHA-256 / MGF1-SHA-256 / 32-byte salt verification matches Wycheproof expectations", () => {
    const rsa = new RSAWrapper();
    runVectors(
      "rsa_pss_2048_sha256_mgf1_32_test.json",
      (key, msg, sig) => rsa.verifyPss(key, msg, sig),
      verifyRsaPss,
    );
  });

  test("RSASSA-PKCS1-v1_5 SHA-256 verification matches Wycheproof expectations", () => {
    const rsa = new RSAWrapper();
    runVectors(
      "rsa_signature_2048_sha256_test.json",
      (key, msg, sig) => rsa.verify(key, msg, sig),
      verifyRsa,
    );
  });
});
