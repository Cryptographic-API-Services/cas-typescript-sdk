import { assert } from "chai";
import { DigitalSignatureFactory, DigitalSignatureType } from "../src-ts/digital-signature/digital-signature-factory";
import { CASRSADigitalSignatureResult } from "../index";

describe("Digital Signature", () => {
    it("SHA 512 RSA pass", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512)
        const tohashed: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(2048, tohashBytes);
        const verify = shaDsWrapper.verifyRSa(dsResult.publicKey, tohashBytes, dsResult.signature);
        assert.equal(verify, true);
    });

    it("SHA 512 RSA fails", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512)
        const tohashed: string = "This is my array to encrypt";
        const notOriginal: string = "This is not a fun time";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
        const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(4096, tohashBytes);
        const verify = shaDsWrapper.verifyRSa(dsResult.publicKey, badBytes, dsResult.signature);
        assert.equal(verify, false);
    });

    it("SHA 256 RSA pass", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256)
        const tohashed: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(2048, tohashBytes);
        const verify = shaDsWrapper.verifyRSa(dsResult.publicKey, tohashBytes, dsResult.signature);
        assert.equal(verify, true);
    });

    it("SHA 256 RSA fails", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256)
        const tohashed: string = "This is my array to encrypt";
        const notOriginal: string = "This is not a fun time";
        const encoder = new TextEncoder();
        const tohashBytes: Array<number> = Array.from(encoder.encode(tohashed));
        const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
        const dsResult: CASRSADigitalSignatureResult = shaDsWrapper.createRsa(4096, tohashBytes);
        const verify = shaDsWrapper.verifyRSa(dsResult.publicKey, badBytes, dsResult.signature);
        assert.equal(verify, false);
    });

    it("SHA 512 ED25519 pass", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512)
        const toHash: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const toHashBytes: Array<number> = Array.from(encoder.encode(toHash));
        const dsResult = shaDsWrapper.createED25519(toHashBytes);
        const verify = shaDsWrapper.verifyED25519(dsResult.publicKey, toHashBytes, dsResult.signature);
        assert.equal(verify, true);
    });

    it("SHA 512 ED25519 fails", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA512)
        const toHash: string = "This is my array to encrypt";
        const notOriginal: string = "This is not a fun time";
        const encoder = new TextEncoder();
        const toHashBytes: Array<number> = Array.from(encoder.encode(toHash));
        const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
        const dsResult = shaDsWrapper.createED25519(toHashBytes);
        const verify = shaDsWrapper.verifyED25519(dsResult.publicKey, badBytes, dsResult.signature);
        assert.equal(verify, false);
    });

    it("SHA 256 ED25519 pass", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256)
        const toHash: string = "This is my array to encrypt";
        const encoder = new TextEncoder();
        const toHashBytes: Array<number> = Array.from(encoder.encode(toHash));
        const dsResult = shaDsWrapper.createED25519(toHashBytes);
        const verify = shaDsWrapper.verifyED25519(dsResult.publicKey, toHashBytes, dsResult.signature);
        assert.equal(verify, true);
    });

    it("SHA 256 ED25519 fails", () => {
        const shaDsWrapper = DigitalSignatureFactory.get(DigitalSignatureType.SHA256)
        const toHash: string = "This is my array to encrypt";
        const notOriginal: string = "This is not a fun time";
        const encoder = new TextEncoder();
        const toHashBytes: Array<number> = Array.from(encoder.encode(toHash));
        const badBytes: Array<number> = Array.from(encoder.encode(notOriginal));
        const dsResult = shaDsWrapper.createED25519(toHashBytes);
        const verify = shaDsWrapper.verifyED25519(dsResult.publicKey, badBytes, dsResult.signature);
        assert.equal(verify, false);
    });
});