import { expect, test } from "@playwright/test";
import { hmacSha512Sign, hmacSha512Verify, hmacSign, hmacVerify } from "../index";
import { HmacWrapper } from "../src-ts/message/hmac";
import {
  MacTestGroup,
  bytesToHex,
  hexToBytes,
  loadWycheproof,
} from "./helpers/wycheproof";

type Sign = (key: number[], message: number[]) => number[];
type Verify = (key: number[], message: number[], tag: number[]) => boolean;

type HmacSuite = {
  name: string;
  fileName: string;
  fullTagBytes: number;
  wrapperSign: Sign;
  wrapperVerify: Verify;
  ffiSign: Sign;
  ffiVerify: Verify;
};

const hmac = new HmacWrapper();

const suites: HmacSuite[] = [
  {
    name: "HMAC-SHA256",
    fileName: "hmac_sha256_test.json",
    fullTagBytes: 32,
    wrapperSign: hmac.hmacSignBytes.bind(hmac),
    wrapperVerify: hmac.hmacVerifyBytes.bind(hmac),
    ffiSign: hmacSign,
    ffiVerify: hmacVerify,
  },
  {
    name: "HMAC-SHA512",
    fileName: "hmac_sha512_test.json",
    fullTagBytes: 64,
    wrapperSign: hmac.hmacSha512SignBytes.bind(hmac),
    wrapperVerify: hmac.hmacSha512VerifyBytes.bind(hmac),
    ffiSign: hmacSha512Sign,
    ffiVerify: hmacSha512Verify,
  },
];

for (const suite of suites) {
  test.describe(`Wycheproof ${suite.name} vectors`, () => {
    test("tag computation matches Wycheproof expectations", () => {
      const file = loadWycheproof<MacTestGroup>(suite.fileName);

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
          const sign = message.length === 0 ? suite.ffiSign : suite.wrapperSign;
          const verify =
            message.length === 0 ? suite.ffiVerify : suite.wrapperVerify;

          // The SDK always emits the full-length tag; Wycheproof groups with
          // a shorter tagSize expect a truncated comparison.
          const computedTag = bytesToHex(sign(key, message).slice(0, tagBytes));
          const isFullTag = tagBytes === suite.fullTagBytes;

          if (vector.result === "valid") {
            expect(computedTag, `${label}: tag mismatch`).toBe(vector.tag);

            if (isFullTag) {
              expect(
                verify(key, message, hexToBytes(vector.tag)),
                `${label}: verify rejected a valid tag`,
              ).toBe(true);
            }
          } else {
            expect(computedTag, `${label}: invalid tag was reproduced`).not.toBe(
              vector.tag,
            );

            if (isFullTag) {
              expect(
                verify(key, message, hexToBytes(vector.tag)),
                `${label}: verify accepted an invalid tag`,
              ).toBe(false);
            }
          }
        }
      }

      expect(vectorsRun).toBe(file.numberOfTests);
    });
  });
}
