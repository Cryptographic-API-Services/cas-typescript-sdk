import {AESWrapper} from "../src-ts/symmetric/index";
import {X25519Wrapper} from "../src-ts/key_exchange/index";
import {CASx25519SecretPublicKeyResult} from "../index";
import { areEqual } from "./helpers/array";
import {test, expect} from '@playwright/test';

test.describe("Insecure Channel Tests", () => {
    test("AES256-GBC Diffie Hellman X25519", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys: CASx25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys: CASx25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      
      const alice_shared_secret = x25519Wrapper.generateSharedSecret(alice_keys.secretKey, bob_keys.publicKey);
      const bob_shared_secret = x25519Wrapper.generateSharedSecret(bob_keys.secretKey, alice_keys.publicKey);

      const alice_aes_key = aesWrapper.aes256KeyNonceX25519DiffieHellman(alice_shared_secret, alice_keys.publicKey, bob_keys.publicKey);
      const bob_aes_key = aesWrapper.aes256KeyNonceX25519DiffieHellman(bob_shared_secret, bob_keys.publicKey, alice_keys.publicKey);
      expect(alice_aes_key.length).toBe(32);
      expect(areEqual(alice_aes_key, bob_aes_key)).toBe(true);

      const tohashed: string = "This is my encrypt text";
      const encoder = new TextEncoder();
      const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));

      const nonce = aesWrapper.generateAESNonce();

      const encrypted = aesWrapper.aes256Encrypt(alice_aes_key, nonce, toEncrypt);
      const decrypted = aesWrapper.aes256Decrypt(bob_aes_key, nonce, encrypted);
      let result = areEqual(decrypted, toEncrypt);
      expect(result).toBe(true);
    });

    test("AES128-GBC Diffie Hellman X25519", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys: CASx25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys: CASx25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      
      const alice_shared_secret = x25519Wrapper.generateSharedSecret(alice_keys.secretKey, bob_keys.publicKey);
      const bob_shared_secret = x25519Wrapper.generateSharedSecret(bob_keys.secretKey, alice_keys.publicKey);

      const alice_aes_key = aesWrapper.aes128KeyNonceX25519DiffieHellman(alice_shared_secret, alice_keys.publicKey, bob_keys.publicKey);
      const bob_aes_key = aesWrapper.aes128KeyNonceX25519DiffieHellman(bob_shared_secret, bob_keys.publicKey, alice_keys.publicKey);
      expect(alice_aes_key.length).toBe(16);
      expect(areEqual(alice_aes_key, bob_aes_key)).toBe(true);

      const tohashed: string = "This is my encrypt text";
      const encoder = new TextEncoder();
      const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));

      const nonce = aesWrapper.generateAESNonce();

      const encrypted = aesWrapper.aes128Encrypt(alice_aes_key, nonce, toEncrypt);
      const decrypted = aesWrapper.aes128Decrypt(bob_aes_key, nonce, encrypted);
      let result = areEqual(decrypted, toEncrypt);
      expect(result).toBe(true);
    });

    test("AES-128 and AES-256 keys from one shared secret are unrelated", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys = x25519Wrapper.generateSecretAndPublicKey();
      const shared_secret = x25519Wrapper.generateSharedSecret(alice_keys.secretKey, bob_keys.publicKey);

      const key_128 = aesWrapper.aes128KeyNonceX25519DiffieHellman(shared_secret, alice_keys.publicKey, bob_keys.publicKey);
      const key_256 = aesWrapper.aes256KeyNonceX25519DiffieHellman(shared_secret, alice_keys.publicKey, bob_keys.publicKey);
      expect(areEqual(key_256.slice(0, 16), key_128)).toBe(false);
    });

    test("A peer that saw a different public key derives a different key", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys = x25519Wrapper.generateSecretAndPublicKey();
      const mallory_keys = x25519Wrapper.generateSecretAndPublicKey();
      const shared_secret = x25519Wrapper.generateSharedSecret(alice_keys.secretKey, bob_keys.publicKey);

      const honest = aesWrapper.aes256KeyNonceX25519DiffieHellman(shared_secret, alice_keys.publicKey, bob_keys.publicKey);
      const substituted = aesWrapper.aes256KeyNonceX25519DiffieHellman(shared_secret, alice_keys.publicKey, mallory_keys.publicKey);
      expect(areEqual(honest, substituted)).toBe(false);
    });

    test("Low-order peer public keys are rejected", () => {
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys = x25519Wrapper.generateSecretAndPublicKey();
      const identity = new Array(32).fill(0);
      const orderOne = [1, ...new Array(31).fill(0)];
      expect(() => x25519Wrapper.generateSharedSecret(alice_keys.secretKey, identity)).toThrow();
      expect(() => x25519Wrapper.generateSharedSecret(alice_keys.secretKey, orderOne)).toThrow();
    });
});