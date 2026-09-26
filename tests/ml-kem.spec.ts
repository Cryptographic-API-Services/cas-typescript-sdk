import { expect, test } from "@playwright/test";
import { MlKem1024Wrapper } from "../src-ts/pqc/ml-kem-wrapper";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { areEqual } from "./helpers/array";

test.describe("ML-KEM-1024 Tests", () => {
  test("encapsulate and decapsulate produce the same shared secret", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    expect(keyPair.publicKey.length).toBe(1568);
    expect(keyPair.secretKey.length).toBe(3168);

    const encap = mlKem.encapsulate(keyPair.publicKey);
    expect(encap.ciphertext.length).toBe(1568);
    expect(encap.sharedSecret.length).toBe(32);

    const sharedSecret = mlKem.decapsulate(keyPair.secretKey, encap.ciphertext);
    expect(areEqual(sharedSecret, encap.sharedSecret)).toBe(true);
  });

  test("decapsulating a tampered ciphertext yields a different shared secret", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    const encap = mlKem.encapsulate(keyPair.publicKey);

    // ML-KEM uses implicit rejection: a tampered ciphertext decapsulates
    // without error but produces an unrelated shared secret.
    const tampered = [...encap.ciphertext];
    tampered[0] ^= 0xff;
    const sharedSecret = mlKem.decapsulate(keyPair.secretKey, tampered);
    expect(areEqual(sharedSecret, encap.sharedSecret)).toBe(false);
  });

  test("each encapsulation yields a fresh ciphertext and shared secret", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    const encap1 = mlKem.encapsulate(keyPair.publicKey);
    const encap2 = mlKem.encapsulate(keyPair.publicKey);
    expect(areEqual(encap1.ciphertext, encap2.ciphertext)).toBe(false);
    expect(areEqual(encap1.sharedSecret, encap2.sharedSecret)).toBe(false);
  });

  test("decapsulating with the wrong secret key yields a different shared secret", () => {
    const mlKem = new MlKem1024Wrapper();
    const recipient = mlKem.generateKeyPair();
    const other = mlKem.generateKeyPair();
    const encap = mlKem.encapsulate(recipient.publicKey);
    const sharedSecret = mlKem.decapsulate(other.secretKey, encap.ciphertext);
    expect(areEqual(sharedSecret, encap.sharedSecret)).toBe(false);
  });

  test("shared secret can key AES-256-GCM", () => {
    const mlKem = new MlKem1024Wrapper();
    const aes = new AESWrapper();
    const keyPair = mlKem.generateKeyPair();
    const encap = mlKem.encapsulate(keyPair.publicKey);
    const senderKey = aes.aes256KeyFromBytes(encap.sharedSecret);
    const recipientKey = aes.aes256KeyFromBytes(mlKem.decapsulate(keyPair.secretKey, encap.ciphertext));

    const nonce = aes.generateAESNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(senderKey, nonce, plaintext);
    expect(areEqual(aes.aes256Decrypt(recipientKey, nonce, ciphertext), plaintext)).toBe(true);
  });

  test("wrong-length inputs throw", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    expect(() => mlKem.encapsulate([1, 2, 3])).toThrow();
    expect(() => mlKem.decapsulate(keyPair.secretKey, [1, 2, 3])).toThrow();
    expect(() => mlKem.decapsulate([1, 2, 3], new Array(1568).fill(0))).toThrow();
  });
});
