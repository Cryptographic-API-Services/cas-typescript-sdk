import { assert } from "chai";
import { X25519Wrapper } from "../src-ts/index";
import { areEqual } from "./helpers/array";

describe("X25519 Key Exchange", () => {
    it("Pass", () => {
    const wrapper = new X25519Wrapper();
    const alice = wrapper.generateSecretAndPublicKey();
    const bob = wrapper.generateSecretAndPublicKey();

    const alice_shared_secret = wrapper.diffieHellman(
      alice.secretKey,
      bob.publicKey,
    );
    const bob_shared_secret = wrapper.diffieHellman(
      bob.secretKey,
      alice.publicKey,
    );

    var result = areEqual(alice_shared_secret, bob_shared_secret);
    assert.isTrue(result);
  });
});
