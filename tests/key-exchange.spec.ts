import {test, expect} from '@playwright/test';
import { X25519Wrapper } from "../src-ts/index";
import { areEqual } from "./helpers/array";

test.describe("X25519 Key Exchange", () => {
    test("Pass", () => {
    const wrapper = new X25519Wrapper();
    const alice = wrapper.generateSecretAndPublicKey();
    const bob = wrapper.generateSecretAndPublicKey();

    const alice_shared_secret = wrapper.generateSharedSecret(
      alice.secretKey,
      bob.publicKey,
    );
    const bob_shared_secret = wrapper.generateSharedSecret(
      bob.secretKey,
      alice.publicKey,
    );

    var result = areEqual(alice_shared_secret, bob_shared_secret);
    expect(result).toBe(true);
  });
});
