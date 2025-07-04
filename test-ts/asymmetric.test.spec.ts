import { assert } from "chai";
import { CASRSAKeyPairResult, RSAWrapper } from "..";

describe("Asymmetric Tests", () => {
    it("RSA 2048 Sign and Verify", () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.generateKeys(2048);
      const tohashed: string = "This is my encrypt";
      const encoder = new TextEncoder();
      const toSignBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      const verified = rsaWrapper.verify(keys.publicKey, toSignBytes, signature);
      assert.isTrue(verified);
    });
});