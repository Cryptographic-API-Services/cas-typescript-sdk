import {AESWrapper} from "../src-ts/symmetric/index";
import {X25519Wrapper} from "../src-ts/key_exchange/index";
import {X25519SecretPublicKeyResult} from "../index";
import { areEqual } from "./helpers/array";
import { assert } from "chai";

describe("Insecure Channel Tests", () => {
    it("AES256-GBC Diffie Hellman X25519", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys: X25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys: X25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      
      const alice_shared_secret = x25519Wrapper.diffieHellman(alice_keys.secretKey, bob_keys.publicKey);
      const bob_shared_secret = x25519Wrapper.diffieHellman(bob_keys.secretKey, alice_keys.publicKey);

      const alice_aes_key = aesWrapper.aes256KeyFromX25519SharedSecret(alice_shared_secret);
      const bob_aes_key = aesWrapper.aes256KeyFromX25519SharedSecret(bob_shared_secret);

      const tohashed: string = "This is my encrypt text";
      const encoder = new TextEncoder();
      const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));

      const encrypted = aesWrapper.aes256Encrypt(alice_aes_key?.aesKey, alice_aes_key?.aesNonce, toEncrypt);
      const decrypted = aesWrapper.aes256Decrypt(bob_aes_key?.aesKey, bob_aes_key?.aesNonce, encrypted);
      let result = areEqual(decrypted, toEncrypt);
      assert.isTrue(result);
    });

    it("AES128-GBC Diffie Hellman X25519", () => {
      const aesWrapper = new AESWrapper();
      const x25519Wrapper = new X25519Wrapper();
      const alice_keys: X25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      const bob_keys: X25519SecretPublicKeyResult = x25519Wrapper.generateSecretAndPublicKey();
      
      const alice_shared_secret = x25519Wrapper.diffieHellman(alice_keys.secretKey, bob_keys.publicKey);
      const bob_shared_secret = x25519Wrapper.diffieHellman(bob_keys.secretKey, alice_keys.publicKey);

      const alice_aes_key = aesWrapper.aes128KeyFromX25519SharedSecret(alice_shared_secret);
      const bob_aes_key = aesWrapper.aes128KeyFromX25519SharedSecret(bob_shared_secret);

      const tohashed: string = "This is my encrypt text";
      const encoder = new TextEncoder();
      const toEncrypt: Array<number> = Array.from(encoder.encode(tohashed));

      const encrypted = aesWrapper.aes128Encrypt(alice_aes_key?.aesKey, alice_aes_key?.aesNonce, toEncrypt);
      const decrypted = aesWrapper.aes128Decrypt(bob_aes_key?.aesKey, bob_aes_key?.aesNonce, encrypted);
      let result = areEqual(decrypted, toEncrypt);
      assert.isTrue(result);
    });
});