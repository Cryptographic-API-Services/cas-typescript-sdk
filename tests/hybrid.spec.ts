import { HpkeWrapper } from "../src-ts/hybrid/hpke";
import { CasErrorCode, isCasError } from "../src-ts/index";
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

    test("HPKE Encrypt and Decrypt with a fixed application-specific info", () => {
        const hpkeWrapper = new HpkeWrapper();
        const keyPair = hpkeWrapper.generateKeyPair();
        const encoder = new TextEncoder();
        const messageBytes: Array<number> = Array.from(encoder.encode("This is a secret message"));
        const info: Array<number> = Array.from(encoder.encode("my-app/v1/file-encryption"));
        const encrypted = hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, info);
        const decrypt = (infoToUse: Array<number>) => hpkeWrapper.decrypt(
            encrypted.ciphertext,
            keyPair.secretKey,
            encrypted.encapsulatedKey,
            encrypted.tag,
            infoToUse
        );
        expect(decrypt(Array.from(encoder.encode("my-app/v1/file-encryption")))).toEqual(messageBytes);
        expect(() => decrypt(Array.from(encoder.encode("my-app/v1/messaging")))).toThrow();
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

    test("HPKE info longer than 65,530 bytes throws CAS_INVALID_INPUT", () => {
        const hpkeWrapper = new HpkeWrapper();
        const keyPair = hpkeWrapper.generateKeyPair();
        const messageBytes: Array<number> = Array.from(new TextEncoder().encode("This is a secret message"));
        const longestInfo: Array<number> = new Array(65_530).fill(0x61);
        const encrypted = hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, longestInfo);
        const decrypt = (infoToUse: Array<number>) => hpkeWrapper.decrypt(
            encrypted.ciphertext,
            keyPair.secretKey,
            encrypted.encapsulatedKey,
            encrypted.tag,
            infoToUse
        );
        expect(decrypt(longestInfo)).toEqual(messageBytes);

        const tooLongInfo: Array<number> = new Array(65_531).fill(0x61);
        const caught = (fn: () => unknown): unknown => {
            try {
                fn();
            } catch (err) {
                return err;
            }
            throw new Error("expected HPKE to throw");
        };
        expect(isCasError(caught(() => hpkeWrapper.encrypt(messageBytes, keyPair.publicKey, tooLongInfo)), CasErrorCode.InvalidInput)).toBe(true);
        expect(isCasError(caught(() => decrypt(tooLongInfo)), CasErrorCode.InvalidInput)).toBe(true);
    });
});