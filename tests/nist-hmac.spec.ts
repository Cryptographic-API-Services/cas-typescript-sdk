import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { HmacWrapper } from "../src-ts/message/hmac";
import { bytesToHex, hexToBytes, parseCavp } from "./helpers/cavp";

// CAVP HMAC.rsp. [L=32] is HMAC-SHA-256 (225 vectors) and [L=64] is HMAC-SHA-512
// (375). Mac is the first Tlen bytes of the full tag. #183.
test.describe("NIST CAVP HMAC", () => {
  const records = parseCavp(fs.readFileSync(path.join(__dirname, "data", "nist", "HMAC.rsp"), "utf8"));

  test("HMAC-SHA-256 and HMAC-SHA-512 match the truncated tag, and a short tag does not verify", () => {
    const hmac = new HmacWrapper();
    const cases = [
      { L: "32", total: 225, full: 75, sign: hmac.hmacSignBytes.bind(hmac), verify: hmac.hmacVerifyBytes.bind(hmac) },
      { L: "64", total: 375, full: 75, sign: hmac.hmacSha512SignBytes.bind(hmac), verify: hmac.hmacSha512VerifyBytes.bind(hmac) },
    ] as const;

    for (const mac of cases) {
      const vectors = records.filter((record) => record.section.L === mac.L);
      expect(vectors.length, `L=${mac.L}`).toBe(mac.total);
      expect(vectors.filter((vector) => vector.fields.Tlen === mac.L).length).toBe(mac.full);

      for (const vector of vectors) {
        const tag = mac.sign(hexToBytes(vector.fields.Key), hexToBytes(vector.fields.Msg));
        const tlen = Number(vector.fields.Tlen);
        expect(bytesToHex(tag.slice(0, tlen))).toBe(vector.fields.Mac.toLowerCase());
        if (vector.fields.Tlen === mac.L) {
          expect(mac.verify(hexToBytes(vector.fields.Key), hexToBytes(vector.fields.Msg), tag)).toBe(true);
        }
      }

      const truncated = vectors.find((vector) => vector.fields.Tlen !== mac.L);
      if (!truncated) {
        throw new Error(`L=${mac.L} has no truncated tag`);
      }
      const full = mac.sign(hexToBytes(truncated.fields.Key), hexToBytes(truncated.fields.Msg));
      const short = full.slice(0, Number(truncated.fields.Tlen));
      expect(mac.verify(hexToBytes(truncated.fields.Key), hexToBytes(truncated.fields.Msg), short)).toBe(false);
    }
  });
});
