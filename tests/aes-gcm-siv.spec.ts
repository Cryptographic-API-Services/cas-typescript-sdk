import { expect, test } from "@playwright/test";
import { AESGCMSIVWrapper } from "../src-ts/symmetric/aes-gcm-siv-wrapper";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { X25519Wrapper } from "../src-ts/key_exchange/x25519";
import { areEqual } from "./helpers/array";

test.describe("AES-GCM-SIV Tests", () => {
  test("aes 128 encrypt and decrypt equals", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes128Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes128Encrypt(key, nonce, plaintext);
    const decrypted = aes.aes128Decrypt(key, nonce, ciphertext);
    expect(areEqual(decrypted, plaintext)).toBe(true);
  });

  test("aes 256 encrypt and decrypt equals", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    const decrypted = aes.aes256Decrypt(key, nonce, ciphertext);
    expect(areEqual(decrypted, plaintext)).toBe(true);
  });

  test("decrypt with wrong key throws", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    const wrongKey = aes.aes256Key();
    expect(() => aes.aes256Decrypt(wrongKey, nonce, ciphertext)).toThrow();
  });

  test("key from bytes validates length", () => {
    const aes = new AESGCMSIVWrapper();
    expect(() => aes.aes128KeyFromBytes([1, 2, 3])).toThrow();
    expect(() => aes.aes256KeyFromBytes([1, 2, 3])).toThrow();
    expect(aes.aes128KeyFromBytes(new Array(16).fill(0)).length).toBe(16);
    expect(aes.aes256KeyFromBytes(new Array(32).fill(0)).length).toBe(32);
  });

  test("key from bytes can encrypt and decrypt", () => {
    const aes = new AESGCMSIVWrapper();
    const encoder = new TextEncoder();
    const plaintext = Array.from(encoder.encode("WelcomeHome"));
    const nonce = aes.generateNonce();

    const key128 = aes.aes128KeyFromBytes(Array.from({ length: 16 }, (_, i) => i));
    const ciphertext128 = aes.aes128Encrypt(key128, nonce, plaintext);
    expect(areEqual(aes.aes128Decrypt(key128, nonce, ciphertext128), plaintext)).toBe(true);

    const key256 = aes.aes256KeyFromBytes(Array.from({ length: 32 }, (_, i) => i));
    const ciphertext256 = aes.aes256Encrypt(key256, nonce, plaintext);
    expect(areEqual(aes.aes256Decrypt(key256, nonce, ciphertext256), plaintext)).toBe(true);
  });

  test("key and nonce sizes", () => {
    const aes = new AESGCMSIVWrapper();
    expect(aes.aes128Key().length).toBe(16);
    expect(aes.aes256Key().length).toBe(32);
    expect(aes.generateNonce().length).toBe(12);
  });

  test("ciphertext carries a 16 byte tag", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    expect(ciphertext.length).toBe(plaintext.length + 16);
  });

  test("decrypt tampered ciphertext throws", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes128Key();
    const nonce = aes.generateNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes128Encrypt(key, nonce, plaintext);
    const tampered = [...ciphertext];
    tampered[0] ^= 0xff;
    expect(() => aes.aes128Decrypt(key, nonce, tampered)).toThrow();
  });

  test("decrypt with wrong nonce throws", () => {
    const aes = new AESGCMSIVWrapper();
    const key = aes.aes256Key();
    const nonce = aes.generateNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(key, nonce, plaintext);
    const wrongNonce = [...nonce];
    wrongNonce[0] ^= 0xff;
    expect(() => aes.aes256Decrypt(key, wrongNonce, ciphertext)).toThrow();
  });

  test("aes 128 X25519 Diffie-Hellman encrypt and decrypt", () => {
    const x25519 = new X25519Wrapper();
    const alice = x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();
    const aliceSharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
    const bobSharedSecret = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);

    const aes = new AESGCMSIVWrapper();
    const aliceKey = aes.aes128KeyFromX25519SharedSecret(aliceSharedSecret, alice.publicKey, bob.publicKey);
    const bobKey = aes.aes128KeyFromX25519SharedSecret(bobSharedSecret, bob.publicKey, alice.publicKey);
    expect(aliceKey.length).toBe(16);
    expect(areEqual(aliceKey, bobKey)).toBe(true);

    const nonce = aes.generateNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes128Encrypt(aliceKey, nonce, plaintext);
    expect(areEqual(aes.aes128Decrypt(bobKey, nonce, ciphertext), plaintext)).toBe(true);
  });

  test("aes 256 X25519 Diffie-Hellman encrypt and decrypt", () => {
    const x25519 = new X25519Wrapper();
    const alice = x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();
    const aliceSharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
    const bobSharedSecret = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);

    const aes = new AESGCMSIVWrapper();
    const aliceKey = aes.aes256KeyFromX25519SharedSecret(aliceSharedSecret, alice.publicKey, bob.publicKey);
    const bobKey = aes.aes256KeyFromX25519SharedSecret(bobSharedSecret, bob.publicKey, alice.publicKey);
    expect(aliceKey.length).toBe(32);
    expect(areEqual(aliceKey, bobKey)).toBe(true);

    const nonce = aes.generateNonce();
    const plaintext = Array.from(new TextEncoder().encode("WelcomeHome"));
    const ciphertext = aes.aes256Encrypt(aliceKey, nonce, plaintext);
    expect(areEqual(aes.aes256Decrypt(bobKey, nonce, ciphertext), plaintext)).toBe(true);
  });

  test("X25519-derived keys are bound to the cipher and to both public keys", () => {
    const x25519 = new X25519Wrapper();
    const alice = x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();
    const mallory = x25519.generateSecretAndPublicKey();
    const sharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);

    const siv = new AESGCMSIVWrapper();
    const gcm = new AESWrapper();
    const siv128 = siv.aes128KeyFromX25519SharedSecret(sharedSecret, alice.publicKey, bob.publicKey);
    const siv256 = siv.aes256KeyFromX25519SharedSecret(sharedSecret, alice.publicKey, bob.publicKey);
    const gcm128 = gcm.aes128KeyNonceX25519DiffieHellman(sharedSecret, alice.publicKey, bob.publicKey);
    const gcm256 = gcm.aes256KeyNonceX25519DiffieHellman(sharedSecret, alice.publicKey, bob.publicKey);

    expect(areEqual(siv128, gcm128)).toBe(false);
    expect(areEqual(siv256, gcm256)).toBe(false);
    expect(areEqual(siv256.slice(0, 16), siv128)).toBe(false);
    expect(areEqual(siv256, siv.aes256KeyFromX25519SharedSecret(sharedSecret, bob.publicKey, alice.publicKey))).toBe(true);
    expect(areEqual(siv256, siv.aes256KeyFromX25519SharedSecret(sharedSecret, alice.publicKey, mallory.publicKey))).toBe(false);
  });

  test("X25519 key derivation rejects malformed inputs", () => {
    const x25519 = new X25519Wrapper();
    const alice = x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();
    const sharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
    const siv = new AESGCMSIVWrapper();

    expect(() => siv.aes256KeyFromX25519SharedSecret(new Array(32).fill(0), alice.publicKey, bob.publicKey)).toThrow();
    expect(() => siv.aes128KeyFromX25519SharedSecret(sharedSecret, alice.publicKey, bob.publicKey.slice(0, 31))).toThrow();
    expect(() => siv.aes128KeyFromX25519SharedSecret(sharedSecret.slice(0, 31), alice.publicKey, bob.publicKey)).toThrow();
  });
});
