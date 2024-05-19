import { assert } from "chai";
import { CASRSAKeyPairResult, RSAWrapper } from "..";
import { areEqual } from "./helpers/array";

describe("Asymmetric Tests", () => {
    it("RSA 4096 encrypt and decrypt equals", () => {
      const rsaWrapper: RSAWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.generateKeys(4096);
      const tohashed: string = "This is my array to encrypt";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const ciphertext = rsaWrapper.encrypt(keys.publicKey, tohashBytes);
      const plaintext = rsaWrapper.decrypt(keys.privateKey, ciphertext);
      let result = areEqual(tohashBytes, plaintext);
      assert.isTrue(result);
    });

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