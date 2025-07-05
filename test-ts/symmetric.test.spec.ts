import { assert } from "chai";
import { AESWrapper } from "../src-ts/symmetric/aes-wrapper";
import { X25519Wrapper } from '../src-ts/key_exchange/x25519';
import { areEqual } from "./helpers/array";

describe("Symmetric Tests", () => {
  it("aes 128 encrypt and decrypt equals", () => {
    const aesWrapper: AESWrapper = new AESWrapper();
    const aesKey = aesWrapper.aes128Key();
    const aesNonce = aesWrapper.generateAESNonce();
    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const ciphertext = aesWrapper.aes128Encrypt(aesKey, aesNonce, tohashBytes);
    const plaintxt = aesWrapper.aes128Decrypt(aesKey, aesNonce, ciphertext);
    var result = areEqual(plaintxt, tohashBytes);
    assert.isTrue(result);
  });

  it("aes 256 encrypt and decrypt equals", () => {
    const aesWrapper: AESWrapper = new AESWrapper();
    const aesKey = aesWrapper.aes256Key();
    const aesNonce = aesWrapper.generateAESNonce();
    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
    const ciphertext = aesWrapper.aes256Encrypt(aesKey, aesNonce, tohashBytes);
    const plaintxt = aesWrapper.aes256Decrypt(aesKey, aesNonce, ciphertext);
    var result = areEqual(plaintxt, tohashBytes);
    assert.isTrue(result);
  });

  it("ase 256 X25519 Diffie-Hellman encrypt and decrypt", () => {
    const x25519 = new X25519Wrapper();
    const alice= x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();

    const aliceSharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
    const bobSharedSecret = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);

    const aesWrapper: AESWrapper = new AESWrapper();
    const aliceAesKey = aesWrapper.aes256KeyNonceX25519DiffieHellman(aliceSharedSecret);
    const bobAesKey = aesWrapper.aes256KeyNonceX25519DiffieHellman(bobSharedSecret);

    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));

    const aliceCiphertext = aesWrapper.aes256Encrypt(aliceAesKey.aesKey, aliceAesKey.aesNonce, tohashBytes);
    const bobPlaintext = aesWrapper.aes256Decrypt(bobAesKey.aesKey, aliceAesKey.aesNonce, aliceCiphertext);

    var result = areEqual(bobPlaintext, tohashBytes);
    assert.isTrue(result);
  });

  it("ase 128 X25519 Diffie-Hellman encrypt and decrypt", () => {
    const x25519 = new X25519Wrapper();
    const alice= x25519.generateSecretAndPublicKey();
    const bob = x25519.generateSecretAndPublicKey();

    const aliceSharedSecret = x25519.generateSharedSecret(alice.secretKey, bob.publicKey);
    const bobSharedSecret = x25519.generateSharedSecret(bob.secretKey, alice.publicKey);

    const aesWrapper: AESWrapper = new AESWrapper();
    const aliceAesKey = aesWrapper.aes128KeyNonceX25519DiffieHellman(aliceSharedSecret);
    const bobAesKey = aesWrapper.aes128KeyNonceX25519DiffieHellman(bobSharedSecret);

    const tohashed: string = "This is my array to encrypt";
    const encoder = new TextEncoder();
    const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));

    const aliceCiphertext = aesWrapper.aes128Encrypt(aliceAesKey.aesKey, aliceAesKey.aesNonce, tohashBytes);
    const bobPlaintext = aesWrapper.aes128Decrypt(bobAesKey.aesKey, aliceAesKey.aesNonce, aliceCiphertext);

    var result = areEqual(bobPlaintext, tohashBytes);
    assert.isTrue(result);
  });
});
