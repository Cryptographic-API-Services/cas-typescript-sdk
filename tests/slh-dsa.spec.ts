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
