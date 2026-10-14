import { expect, test } from "@playwright/test";
import { MlDsa65Wrapper } from "../src-ts/pqc/ml-dsa-wrapper";

test.describe("ML-DSA-65 Tests", () => {
  test("sign and verify", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    expect(keyPair.signingKey.length).toBe(32);
    expect(keyPair.verificationKey.length).toBe(1952);

    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = mlDsa.sign(message, keyPair.signingKey);
    const verified = mlDsa.verify(message, signature, keyPair.verificationKey);
    expect(verified).toBe(true);
    expect(signature.length).toBe(3309);
  });

  test("signing is deterministic", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const first = mlDsa.sign(message, keyPair.signingKey);
    const second = mlDsa.sign(message, keyPair.signingKey);
    expect(second).toEqual(first);
  });

  test("verify fails for a tampered message", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = mlDsa.sign(message, keyPair.signingKey);
    const tampered = Array.from(encoder.encode("ThisIsMyMessageToSign2"));
    const verified = mlDsa.verify(tampered, signature, keyPair.verificationKey);
    expect(verified).toBe(false);
  });

  test("verify fails with a different key pair's verification key", () => {
    const mlDsa = new MlDsa65Wrapper();
    const signer = mlDsa.generateKeyPair();
    const other = mlDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = mlDsa.sign(message, signer.signingKey);
    expect(mlDsa.verify(message, signature, other.verificationKey)).toBe(false);
  });

  test("verify fails for a tampered signature", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = mlDsa.sign(message, keyPair.signingKey);
    const tampered = [...signature];
    // Flip a byte of the commitment hash c~; the trailing bytes encode hints and
    // would make the signature unparseable (which throws) rather than invalid.
    tampered[0] ^= 0xff;
    expect(mlDsa.verify(message, tampered, keyPair.verificationKey)).toBe(false);
  });

  test("wrong-length signature throws", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    expect(() => mlDsa.verify(message, [1, 2, 3], keyPair.verificationKey)).toThrow();
  });

  test("wrong-length keys throw", () => {
    const mlDsa = new MlDsa65Wrapper();
    const keyPair = mlDsa.generateKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    expect(() => mlDsa.sign(message, [1, 2, 3])).toThrow();
    const signature = mlDsa.sign(message, keyPair.signingKey);
    expect(() => mlDsa.verify(message, signature, [1, 2, 3])).toThrow();
  });
});
