import { expect, test } from "@playwright/test";
import { SlhDsaWrapper } from "../src-ts/pqc/slh-dsa-wrapper";

test.describe("SLH-DSA Tests", () => {
  test("sign and verify", () => {
    const slhDsa = new SlhDsaWrapper();
    const keyPair = slhDsa.generateKeyPair();
    expect(keyPair.signingKey.length).toBe(64);
    expect(keyPair.verificationKey.length).toBe(32);

    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = slhDsa.sign(message, keyPair.signingKey);
    const verified = slhDsa.verify(message, signature, keyPair.verificationKey);
    expect(verified).toBe(true);
  });

  test("verify fails for a tampered message", () => {
    const slhDsa = new SlhDsaWrapper();
    const keyPair = slhDsa.generateKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = slhDsa.sign(message, keyPair.signingKey);
    const tampered = Array.from(encoder.encode("ThisIsMyMessageToSign2"));
    const verified = slhDsa.verify(tampered, signature, keyPair.verificationKey);
    expect(verified).toBe(false);
  });

  test("verify fails with a different key pair's verification key", () => {
    const slhDsa = new SlhDsaWrapper();
    const signer = slhDsa.generateKeyPair();
    const other = slhDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = slhDsa.sign(message, signer.signingKey);
    expect(slhDsa.verify(message, signature, other.verificationKey)).toBe(false);
  });

  test("verify fails for a tampered signature", () => {
    const slhDsa = new SlhDsaWrapper();
    const keyPair = slhDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = slhDsa.sign(message, keyPair.signingKey);
    const tampered = [...signature];
    tampered[tampered.length - 1] ^= 0xff;
    expect(slhDsa.verify(message, tampered, keyPair.verificationKey)).toBe(false);
  });

  test("wrong-length signature throws", () => {
    const slhDsa = new SlhDsaWrapper();
    const keyPair = slhDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    expect(() => slhDsa.verify(message, [1, 2, 3], keyPair.verificationKey)).toThrow();
  });

  test("wrong-length keys throw", () => {
    const slhDsa = new SlhDsaWrapper();
    const keyPair = slhDsa.generateKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    expect(() => slhDsa.sign(message, [1, 2, 3])).toThrow();
    const signature = slhDsa.sign(message, keyPair.signingKey);
    expect(() => slhDsa.verify(message, signature, [1, 2, 3])).toThrow();
  });
});
