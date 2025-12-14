import { test, expect } from '@playwright/test';
import { RSAWrapper, CASRSAKeyPairResult } from '../src-ts/asymmetric/index';

test('RSA Verify', async ({ page }) => {
  const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.generateKeys(2048);
      const tohashed: string = "This is my encrypt";
      const encoder = new TextEncoder();
      const toSignBytes: Array<number> = Array.from(encoder.encode(tohashed));
      const signature: Array<number> = rsaWrapper.sign(keys.privateKey, toSignBytes);
      const verified = rsaWrapper.verify(keys.publicKey, toSignBytes, signature);
      expect(verified).toBe(true);
});
