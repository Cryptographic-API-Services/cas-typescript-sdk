import { AsconWrapper } from "../src-ts/sponges/ascon-wrapper";
import {test, expect} from '@playwright/test';
import { areEqual } from "./helpers/array";

test.describe("Sponges Tests", () => {
    test("Ascon 128 Encrypt", () => {
        const wrapper: AsconWrapper = new AsconWrapper();
        const key: Array<number> = wrapper.ascon128Key();
        const nonce: Array<number> = wrapper.ascon128Nonce();
        const tohashed: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const ciphertext = wrapper.ascon128Encrypt(key, nonce, tohashBytes);
        expect(areEqual(tohashBytes, ciphertext)).toBe(false);
    });

    test("Ascon 128 Decrypt", () => {
        const wrapper: AsconWrapper = new AsconWrapper();
        const key: Array<number> = wrapper.ascon128Key();
        const nonce: Array<number> = wrapper.ascon128Nonce();
        const tohashed: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const ciphertext = wrapper.ascon128Encrypt(key, nonce, tohashBytes);
        const plaintext = wrapper.ascon128Decrypt(key, nonce, ciphertext);
        expect(areEqual(plaintext, tohashBytes)).toBe(true);
    });
});