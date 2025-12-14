import { test, expect } from "@playwright/test";
import {
  DigitalSignatureFactory,
  DigitalSignatureType,
} from "../src-ts/digital-signature/digital-signature-factory";
import { CASRSADigitalSignatureResult } from "../index";
import { Ed25519Wrapper } from "../src-ts/signature/ed25519-wrapper";

test("SHA 512 RSA pass", () => {
  const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512);
  const tohashed: string = "This is my array to encrypt";
  const encoder = new TextEncoder();
  const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
  const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(
    2048,
    tohashBytes
  );
  const verify = shaDsWrapper.verifyRSa(
    dsResult.publicKey,
    tohashBytes,
    dsResult.signature
  );
  expect(verify).toBe(true);
});

test("SHA 512 RSA fails", () => {
  const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512);
  const tohashed: string = "This is my array to encrypt";
  const notOriginal: string = "This is not a fun time";
  const encoder = new TextEncoder();
  const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
  const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
  const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(
    4096,
    tohashBytes
  );
  const verify = shaDsWrapper.verifyRSa(
    dsResult.publicKey,
    badBytes,
    dsResult.signature
  );
  expect(verify).toBe(false);
});

test("SHA 256 RSA pass", () => {
  const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256);
  const tohashed: string = "This is my array to encrypt";
  const encoder = new TextEncoder();
  const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
  const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(
    2048,
    tohashBytes
  );
  const verify = shaDsWrapper.verifyRSa(
    dsResult.publicKey,
    tohashBytes,
    dsResult.signature
  );
  expect(verify).toBe(true);
});

test("SHA 256 RSA fails", () => {
  const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256);
  const tohashed: string = "This is my array to encrypt";
  const notOriginal: string = "This is not a fun time";
  const encoder = new TextEncoder();
  const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
  const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
  const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(
    4096,
    tohashBytes
  );
  const verify = shaDsWrapper.verifyRSa(
    dsResult.publicKey,
    badBytes,
    dsResult.signature
  );
  expect(verify).toBe(false);
});

test("ED25519 Sign and Verify", () => {
  const ed25519 = new Ed25519Wrapper();
  const keyPair = ed25519.getKeyPair();
  const message = Array.from(
    new TextEncoder().encode("This is a test message")
  );
  const signature = ed25519.signMessage(keyPair.privateKey, message);
  const isValid = ed25519.verifyMessage(keyPair.publicKey, message, signature);
  expect(isValid).toBe(true);
});

test("ED25519 Verify Fails with Wrong Message", () => {
  const ed25519 = new Ed25519Wrapper();
  const keyPair = ed25519.getKeyPair();
  const message = Array.from(
    new TextEncoder().encode("This is a test message")
  );
  const wrongMessage = Array.from(
    new TextEncoder().encode("This is a different message")
  );
  const signature = ed25519.signMessage(keyPair.privateKey, message);
  const isValid = ed25519.verifyMessage(
    keyPair.publicKey,
    wrongMessage,
    signature
  );
  expect(isValid).toBe(false);
});
