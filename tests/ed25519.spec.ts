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
});
