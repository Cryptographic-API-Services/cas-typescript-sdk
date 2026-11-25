import { test, expect } from '@playwright/test';
import * as crypto from 'crypto';
import { RSAWrapper, CASRSAKeyPairResult } from '../src-ts/asymmetric/index';

test('RSA Verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.getKeyPair(2048);
      const message: string = "This is my message";
      const encoder = new TextEncoder();
      const toSignBytes: Array<number> = Array.from(encoder.encode(message));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      const verified = rsaWrapper.verify(keys.publicKey, toSignBytes, signature);
      expect(verified).toBe(true);
});

test('RSA 3072 bit keys sign and verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.getKeyPair(3072);
      const toSignBytes: Array<number> = Array.from(new TextEncoder().encode("This is my message"));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      expect(rsaWrapper.verify(keys.publicKey, toSignBytes, signature)).toBe(true);
});

test('RSA rejects key sizes under 2048 bits', async () => {
      const rsaWrapper = new RSAWrapper();
      expect(() => rsaWrapper.getKeyPair(1024)).toThrow(/2048, 3072 or 4096/);
});

test('RSA signs messages longer than the modulus', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys = rsaWrapper.getKeyPair(2048);
      const message: Array<number> = Array.from(crypto.randomBytes(10_000));
      const signature = rsaWrapper.sign(keys.privateKey, message);
      expect(signature.length).toBe(256);
      expect(rsaWrapper.verify(keys.publicKey, message, signature)).toBe(true);
      message[0] ^= 1;
      expect(rsaWrapper.verify(keys.publicKey, message, signature)).toBe(false);
});

test('RSA signature from Node crypto RS256 verifies with RSAWrapper', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys = rsaWrapper.getKeyPair(2048);
      const message = Buffer.from("Signed by Node, verified by cas-typescript-sdk");
      const nodeSignature = crypto.sign('sha256', message, keys.privateKey);
      expect(rsaWrapper.verify(keys.publicKey, Array.from(message), Array.from(nodeSignature))).toBe(true);
});

test('RSA signature from RSAWrapper verifies with Node crypto RS256', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys = rsaWrapper.getKeyPair(2048);
      const message = Buffer.from("Signed by cas-typescript-sdk, verified by Node");
      const signature = Buffer.from(rsaWrapper.sign(keys.privateKey, Array.from(message)));
      expect(crypto.verify('sha256', message, keys.publicKey, signature)).toBe(true);
      expect(crypto.verify('sha256', Buffer.from("something else"), keys.publicKey, signature)).toBe(false);
});

test('RSA signatures from Node keys verify, and RS256 is deterministic', async () => {
      const rsaWrapper = new RSAWrapper();
      const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      });
      const message = Array.from(Buffer.from("Node-generated key pair"));
      const signature = rsaWrapper.sign(privateKey, message);
      expect(Buffer.from(signature).equals(crypto.sign('sha256', Buffer.from(message), privateKey))).toBe(true);
      expect(rsaWrapper.verify(publicKey, message, signature)).toBe(true);
});

test('RSA 1.x-style signatures (PKCS#1 v1.5 without DigestInfo) no longer verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys = rsaWrapper.getKeyPair(2048);
      const message = Buffer.from("old format");
      const digest = crypto.createHash('sha256').update(message).digest();
      const legacySignature = crypto.privateEncrypt(
            { key: keys.privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            digest,
      );
      expect(rsaWrapper.verify(keys.publicKey, Array.from(message), Array.from(legacySignature))).toBe(false);
      expect(rsaWrapper.verify(keys.publicKey, Array.from(digest), Array.from(legacySignature))).toBe(false);
});
