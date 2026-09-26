import { expect, test } from "@playwright/test";
import { Ed25519Wrapper } from "../src-ts/signature/ed25519-wrapper";

test.describe("Ed25519 Tests", () => {
  test("sign and verify with public key", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(keyPair.privateKey, message);
    expect(ed25519.verifyBytes(keyPair.publicKey, message, signature)).toBe(true);
  });

  test("sign and verify with key pair", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    const encoder = new TextEncoder();
    const message = Array.from(encoder.encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(keyPair.privateKey, message);
    expect(
      ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, signature),
    ).toBe(true);

    const tampered = Array.from(encoder.encode("ThisIsMyMessageToSign2"));
    expect(
      ed25519.verifyWithKeyPairBytes(keyPair.privateKey, tampered, signature),
    ).toBe(false);
  });

  test("verify with a different key pair fails", () => {
    const ed25519 = new Ed25519Wrapper();
    const signer = ed25519.getKeyPair();
    const other = ed25519.getKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(signer.privateKey, message);
    expect(ed25519.verifyWithKeyPairBytes(other.privateKey, message, signature)).toBe(false);
  });

  test("verify with key pair rejects a tampered signature", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(keyPair.privateKey, message);
    const tampered = [...signature];
    tampered[0] ^= 0xff;
    expect(ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, tampered)).toBe(false);
  });

  test("verify with key pair and public key agree", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(keyPair.privateKey, message);
    expect(ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, signature)).toBe(
      ed25519.verifyBytes(keyPair.publicKey, message, signature),
    );
  });

  test("verify with key pair throws on wrong-length inputs", () => {
    const ed25519 = new Ed25519Wrapper();
    const keyPair = ed25519.getKeyPair();
    const message = Array.from(new TextEncoder().encode("ThisIsMyMessageToSign"));
    const signature = ed25519.signBytes(keyPair.privateKey, message);
    expect(() => ed25519.verifyWithKeyPairBytes([1, 2, 3], message, signature)).toThrow();
    expect(() => ed25519.verifyWithKeyPairBytes(keyPair.privateKey, message, [1, 2, 3])).toThrow();
  });
});
