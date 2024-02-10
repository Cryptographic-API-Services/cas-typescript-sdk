import { assert } from "chai";
import {
  AESRSAHybridInitializer,
  AesRsaHybridEncryptResult,
  HybridEncryptionWrapper,
} from "../src-ts/hybrid/index";
import { areEqual } from "./helpers/array";

describe("Hybrid Encryption Tests", () => {
  it("RSA 4096 AES 128 encrypt and decrypt equals", () => {
    const hybridWrapper = new HybridEncryptionWrapper();
    let initalizer = new AESRSAHybridInitializer(128, 4096);
    const tohashed: string = "This is my encrypt text for rsa hybrid";
    const encoder = new TextEncoder();
    const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));
    let result: AesRsaHybridEncryptResult = hybridWrapper.encrypt(toEncrypt, initalizer);
    let plaintext: Array<number> = hybridWrapper.decrypt(initalizer.rsaKeyPair.privateKey, result);
    let result2 = areEqual(toEncrypt, plaintext);
    assert.isTrue(result2);
  });

  it("RSA 2048 AES 256 encrypt and decrypt equals", () => {
    const hybridWrapper = new HybridEncryptionWrapper();
    let initalizer = new AESRSAHybridInitializer(256, 2048);
    const tohashed: string = "This is my encrypt text for rsa hybrid";
    const encoder = new TextEncoder();
    const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));
    let result: AesRsaHybridEncryptResult = hybridWrapper.encrypt(toEncrypt, initalizer);
    let plaintext: Array<number> = hybridWrapper.decrypt(initalizer.rsaKeyPair.privateKey, result);
    let result2 = areEqual(toEncrypt, plaintext);
    assert.isTrue(result2);
  });
});
