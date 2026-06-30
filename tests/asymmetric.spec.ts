import { test, expect } from '@playwright/test';
import { RSAWrapper, CASRSAKeyPairResult } from '../src-ts/asymmetric/index';

test('RSA Verify', async () => {
      const rsaWrapper = new RSAWrapper();
      const keys: CASRSAKeyPairResult = rsaWrapper.getKeyPair(2048);
      const tohashed: string = "This is my encrypt";
      const encoder = new TextEncoder();
      const toSignBytes: Uint8Array = encoder.encode(tohashed);
      const signature: Uint8Array = rsaWrapper.sign(keys.privateKey, toSignBytes);
      const verified = rsaWrapper.verify(keys.publicKey, toSignBytes, signature);
      expect(verified).toBe(true);
});
