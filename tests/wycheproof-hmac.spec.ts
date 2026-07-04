import { expect, test } from "@playwright/test";
import { hmacSign, hmacVerify } from "../index";
import { HmacWrapper } from "../src-ts/message/hmac";
import {
  MacTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

test.describe("Wycheproof HMAC-SHA256 vectors", () => {
  test("tag computation matches Wycheproof expectations", () => {
    const hmac = new HmacWrapper();
    const file = loadWycheproof<MacTestGroup>("hmac_sha256_test.json");

    let vectorsRun = 0;

    for (const group of file.testGroups) {
      const tagBytes = group.tagSize / 8;

      for (const vector of group.tests) {
        const label = `tcId ${vector.tcId} (${vector.comment})`;
        const key = hexToBytes(vector.key);
        const message = hexToBytes(vector.msg);
        vectorsRun++;

        // HmacWrapper rejects empty messages up front, so empty-message
        // vectors go through the FFI functions the wrapper delegates to.
        const sign = message.length === 0 ? hmacSign : hmac.hmacSignBytes.bind(hmac);
        const verify =
          message.length === 0 ? hmacVerify : hmac.hmacVerifyBytes.bind(hmac);

        // The SDK always emits the full 32-byte tag; Wycheproof groups with
        // tagSize 128 expect a truncated comparison.
        const computedTag = bytesToHex(sign(key, message).slice(0, tagBytes));

        if (vector.result === "valid") {
          expect(computedTag, `${label}: tag mismatch`).toBe(vector.tag);

          if (tagBytes === 32) {
            expect(
              verify(key, message, hexToBytes(vector.tag)),
              `${label}: hmacVerify rejected a valid tag`,
            ).toBe(true);
          }
        } else {
          expect(computedTag, `${label}: invalid tag was reproduced`).not.toBe(
            vector.tag,
          );

          if (tagBytes === 32) {
            expect(
              verify(key, message, hexToBytes(vector.tag)),
              `${label}: hmacVerify accepted an invalid tag`,
            ).toBe(false);
          }
        }
      }
    }

    expect(vectorsRun).toBe(file.numberOfTests);
  });
});
