import { assert } from "chai";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { areEqual } from "./helpers/array";

describe("Symmetric Tests", () => {
  it("aes 128 encrypt and decrypt equals", () => {
    const aesWrapper: AESWrapper = new AESWrapper();
    const aesKey = aesWrapper.aes128Key();
    const aesNonce = aesWrapper.aesNonce();
    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const ciphertext = aesWrapper.aes128Encrypt(aesKey, aesNonce, tohashBytes);
    const plaintxt = aesWrapper.aes128Decrypt(aesKey, aesNonce, ciphertext);
    var result = areEqual(plaintxt, tohashBytes);
    assert.isTrue(result);
  });

  it("aes 256 encrypt and decrypt equals", () => {
    const aesWrapper: AESWrapper = new AESWrapper();
    const aesKey = aesWrapper.aes256Key();
    const aesNonce = aesWrapper.aesNonce();
    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const ciphertext = aesWrapper.aes256Encrypt(aesKey, aesNonce, tohashBytes);
    const plaintxt = aesWrapper.aes256Decrypt(aesKey, aesNonce, ciphertext);
    var result = areEqual(plaintxt, tohashBytes);
    assert.isTrue(result);
  });
});
