import { HpkeWrapper } from "../src-ts/hybrid/hpke";
import {test, expect} from '@playwright/test';

test.describe("Hybrid Encryption", () => {
    test("HPKE Encrypt and Decrypt", () => {
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
        expect(decryptedMessage).toBe(message);
    });

    test("HPKE Encrypt and Decrypt with AAD", () => {
        const hpkeWrapper = new HpkeWrapper();
        const keyPair = hpkeWrapper.generateKeyPair();
        const encoder = new TextEncoder();
        const messageBytes: Array<number> = Array.from(encoder.encode("This is a secret message"));
        const aad: Array<number> = Array.from(encoder.encode("message-id: 42"));
        const encrypted = hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, keyPair.infoStr, aad);
        const decrypt = (aadToUse?: Array<number>) => hpkeWrapper.decrypt(
            encrypted.ciphertext,
            keyPair.secretKey,
            encrypted.encapsulatedKey,
            encrypted.tag,
            keyPair.infoStr,
            aadToUse
        );
        expect(decrypt(aad)).toEqual(messageBytes);
        expect(() => decrypt(Array.from(encoder.encode("message-id: 43")))).toThrow();
        expect(() => decrypt()).toThrow();
    });

    test("HPKE Decrypt with AAD fails when encrypted without it", () => {
        const hpkeWrapper = new HpkeWrapper();
        const keyPair = hpkeWrapper.generateKeyPair();
        const messageBytes: Array<number> = Array.from(new TextEncoder().encode("This is a secret message"));
        const encrypted = hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, keyPair.infoStr);
        expect(() => hpkeWrapper.decrypt(
            encrypted.ciphertext,
            keyPair.secretKey,
            encrypted.encapsulatedKey,
            encrypted.tag,
            keyPair.infoStr,
            [1, 2, 3]
        )).toThrow();
    });
});