import { CASRSADigitalSignatureResult, CASSHAED25519DalekDigitalSignatureResult, sha512Ed25519DigitalSignature, sha512Ed25519DigitalSignatureVerify, sha512RsaDigitalSignature, sha512RsaVerifyDigitalSignature } from "../../index";
import { IDigitalSignature } from "./digital-signature-base";

export class DigitalSignatureSHA512Wrapper implements IDigitalSignature {

    /**
     * Creates an ED25519 siganture from an array of bytes with SHA3-512.
     * @param dataToSign 
     * @returns CASSHAED25519DalekDigitalSignatureResult
     */
    createED25519(dataToSign: number[]): CASSHAED25519DalekDigitalSignatureResult {
        if (dataToSign?.length === 0) {
            throw new Error("Must provide allocated data to sign");
        }
        return sha512Ed25519DigitalSignature(dataToSign);
    }

    /**
     * Verifies an ED25519 signature with the public key generated from running createED25519() with SHA3-512
     * @param publicKey 
     * @param dataToVerify 
     * @param signature 
     * @returns boolean
     */
    verifyED25519(publicKey: number[], dataToVerify: number[], signature: number[]): boolean {
        if (!publicKey) {
            throw new Error("You must provide a public key for verify with ED25519");
        }
        if (dataToVerify?.length === 0) {
            throw new Error("Must provide allocated data to verify");
        }
        if (signature?.length === 0) {
            throw new Error("Must provide allocated signature to verify");
        }
        return sha512Ed25519DigitalSignatureVerify(publicKey, dataToVerify, signature);
    }

    /**
     * Generates and RSA digital signature with SHA3-512
     * @param rsa_key_size 
     * @param data_to_sign 
     * @returns CASRSADigitalSignatureResult
     */
    createRsa(rsa_key_size: number, data_to_sign: number[]): CASRSADigitalSignatureResult {
        if (rsa_key_size !== 1024 && rsa_key_size !== 2048 && rsa_key_size !== 4096) {
            throw new Error("You need to provide an appropriate RSA key size.");
        }
        if (data_to_sign?.length === 0) {
            throw new Error("Must provide allocated data to sign");
        }
        return sha512RsaDigitalSignature(rsa_key_size, data_to_sign);
    }
    
    /**
     * Verifies a digital signature created with the RSA public key.
     * @param public_key 
     * @param data_to_verify 
     * @param signature 
     * @returns boolean
     */
    verifyRSa(public_key: string, data_to_verify: number[], signature: number[]): boolean {
        if (!public_key) {
            throw new Error("Must provide a public key");
        }
        if (data_to_verify?.length === 0) {
            throw new Error("Must provide an allocated data to verify");
        }
        if (signature?.length === 0) {
            throw new Error("Must provide an allocated signature");
        }
        return sha512RsaVerifyDigitalSignature(public_key, data_to_verify, signature);
    }
}