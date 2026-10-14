import { expect, test } from "@playwright/test";
import { MlDsa65Wrapper } from "../src-ts/pqc/ml-dsa-wrapper";
import { bytesToHex, hexToBytes, loadWycheproof, WycheproofResult } from "./helpers/wycheproof";

type MlDsaSignTest = {
  tcId: number;
  comment: string;
  flags: string[];
  msg?: string;
  mu?: string;
  ctx?: string;
  rnd?: string;
  sig: string;
  result: WycheproofResult;
};

type MlDsaSignTestGroup = {
  privateSeed: string;
  publicKey: string;
  tests: MlDsaSignTest[];
};

type MlDsaVerifyTest = {
  tcId: number;
  comment: string;
  flags: string[];
  msg: string;
  ctx?: string;
  sig: string;
  result: WycheproofResult;
};

type MlDsaVerifyTestGroup = {
  publicKey: string;
  tests: MlDsaVerifyTest[];
};

// The SDK signs with the deterministic variant of ML-DSA-65 over the full
// message with an empty context string, so vectors that need a non-empty
// context, a hedged `rnd` value, or a precomputed μ (Sign_internal) cannot be
// expressed through its API and are skipped. The expected skip counts are
// pinned so a vector cannot be silently dropped.
function unsupportedReason(vector: { ctx?: string; rnd?: string; msg?: string }): string | undefined {
  if (vector.ctx) {
    return "context";
  }
  if (vector.rnd) {
    return "hedged";
  }
  if (vector.msg === undefined) {
    return "internal";
  }
  return undefined;
}

const LENGTH_FLAGS = ["IncorrectPublicKeyLength", "IncorrectSignatureLength"];

test.describe("Wycheproof ML-DSA-65 vectors", () => {
  test("deterministic signing from a seed matches Wycheproof signatures", () => {
    const mlDsa = new MlDsa65Wrapper();
    const file = loadWycheproof<MlDsaSignTestGroup>("mldsa_65_sign_seed_test.json");

    let vectorsRun = 0;
    const skipped: Record<string, number> = {};

    for (const group of file.testGroups) {
      const signingKey = hexToBytes(group.privateSeed);
      const verificationKey = hexToBytes(group.publicKey);

      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const reason = unsupportedReason(vector);
        if (reason) {
          skipped[reason] = (skipped[reason] ?? 0) + 1;
          continue;
        }
        vectorsRun++;

        const message = hexToBytes(vector.msg!);
        if (vector.result === "valid") {
          const signature = mlDsa.sign(message, signingKey);
          expect(bytesToHex(signature), `${label}: signature mismatch`).toBe(vector.sig);
          expect(
            mlDsa.verify(message, signature, verificationKey),
            `${label}: own signature did not verify`,
          ).toBe(true);
        } else {
          expect(
            () => mlDsa.sign(message, signingKey),
            `${label}: signing accepted an invalid private key`,
          ).toThrow();
        }
      }
    }

    expect(skipped).toEqual({ context: 4, hedged: 1, internal: 17 });
    expect(vectorsRun + 22).toBe(file.numberOfTests);
  });

  test("verification matches Wycheproof expectations", () => {
    const mlDsa = new MlDsa65Wrapper();
    const file = loadWycheproof<MlDsaVerifyTestGroup>("mldsa_65_verify_test.json");

    let vectorsRun = 0;
    let skipped = 0;

    for (const group of file.testGroups) {
      const verificationKey = hexToBytes(group.publicKey);

      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        if (unsupportedReason(vector)) {
          skipped++;
          continue;
        }
        vectorsRun++;

        const message = hexToBytes(vector.msg);
        const signature = hexToBytes(vector.sig);

        if (vector.result === "valid") {
          expect(
            mlDsa.verify(message, signature, verificationKey),
            `${label}: valid signature rejected`,
          ).toBe(true);
        } else if (vector.flags.some((flag) => LENGTH_FLAGS.includes(flag))) {
          expect(
            () => mlDsa.verify(message, signature, verificationKey),
            `${label}: wrong-length input did not throw`,
          ).toThrow();
        } else {
          // cas-lib throws when the signature cannot be decoded (e.g. a
          // malformed hint encoding or a z coefficient outside the norm bound)
          // and returns false when it decodes but does not verify. Either way
          // the signature must be rejected.
          let accepted: boolean;
          try {
            accepted = mlDsa.verify(message, signature, verificationKey);
          } catch {
            accepted = false;
          }
          expect(accepted, `${label}: invalid signature accepted`).toBe(false);
        }
      }
    }

    expect(skipped).toBe(7);
    expect(vectorsRun + skipped).toBe(file.numberOfTests);
  });
});
