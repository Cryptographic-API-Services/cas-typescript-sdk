import { assert } from "chai";
import { RSAWrapper, RsaKeyPairResult } from "..";
import { areEqual } from "./helpers/array";

describe("Asymmetric Tests", () => {
    it("RSA 4096 encrypt and decrypt equals", () => {
      const rsaWrapper: RSAWrapper = new RSAWrapper();
      const keys: RsaKeyPairResult = rsaWrapper.generateKeys(4096);
      const tohashed: string = "This is my array to encrypt";
      const encoder = new TextEncoder();
      const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const ciphertext = rsaWrapper.encrypt(keys.publicKey, tohashBytes);
      const plaintext = rsaWrapper.decrypt(keys.privateKey, ciphertext);
      let result = areEqual(tohashBytes, plaintext);
      assert.isTrue(result);
    });
});