import { expect, test } from "@playwright/test";
import { MlKem1024Wrapper } from "../src-ts/pqc/ml-kem-wrapper";
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

  test("wrong-length inputs throw", () => {
    const mlKem = new MlKem1024Wrapper();
    const keyPair = mlKem.generateKeyPair();
    expect(() => mlKem.encapsulate([1, 2, 3])).toThrow();
    expect(() => mlKem.decapsulate(keyPair.secretKey, [1, 2, 3])).toThrow();
    expect(() => mlKem.decapsulate([1, 2, 3], new Array(1568).fill(0))).toThrow();
  });
});
