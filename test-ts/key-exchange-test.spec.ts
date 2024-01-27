import { assert } from "chai";
import {X25519Wrapper} from "../src-ts/index";

describe("X25519 Key Exchange", () => {
  test("Pass", () => {
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

    const areEqual = (a, b) => {
        if (a === b) return true;
        if (a == null || b == null) return false;
        if (a.length !== b.length) return false;

        for (var i = 0; i < a.length; ++i) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    };

    var result = areEqual(alice_shared_secret, bob_shared_secret);
    assert.isTrue(result);
  });
});
