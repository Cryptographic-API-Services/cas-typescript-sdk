import { HpkeWrapper } from "../src-ts/hybrid/hpke";
import { assert } from "chai";

describe("Hybrid Encryption", () => {
    it("HPKE Encrypt and Decrypt", () => {
        const hpkeWrapper = new HpkeWrapper();
        const keyPair = hpkeWrapper.generateKeyPair();
        const encoder = new TextEncoder();
        const message = "This is a secret message";
        const messageBytes: Array<number> = Array.from(encoder.encode(message));
        const encrypted = hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, keyPair.infoStr);
        const decrypted = hpkeWrapper.decrypt(
            encrypted.ciphertext,
            keyPair.secretKey,
            encrypted.encapsulatedKey,
            encrypted.tag,
            keyPair.infoStr
        );
        const decoder = new TextDecoder();
        const decryptedMessage = decoder.decode(new Uint8Array(decrypted));
        assert.equal(decryptedMessage, message);
    });
});