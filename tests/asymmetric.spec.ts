import { test, expect } from '@playwright/test';
import { RSAWrapper, CASRSAKeyPairResult } from '../src-ts/asymmetric/index';

test('RSA Verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.getKeyPair(2048);
      const tohashed: string = "This is my encrypt";
      const encoder = new TextEncoder();
      const toSignBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      const verified = rsaWrapper.verify(keys.publicKey, toSignBytes, signature);
      expect(verified).toBe(true);
});

test('RSA 3072 bit keys sign and verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.getKeyPair(3072);
      const toSignBytes: Array<number> = Array.from(new TextEncoder().encode("This is my encrypt"));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      expect(rsaWrapper.verify(keys.publicKey, toSignBytes, signature)).toBe(true);
});

test('RSA rejects key sizes under 2048 bits', async () => {
      const rsaWrapper = new RSAWrapper();
      expect(() => rsaWrapper.getKeyPair(1024)).toThrow(/2048, 3072 or 4096/);
});
