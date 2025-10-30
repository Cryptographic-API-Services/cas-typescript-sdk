import { CASRSADigitalSignatureResult, CASSHAED25519DalekDigitalSignatureResult, sha512RsaDigitalSignature, sha512RsaVerifyDigitalSignature } from "../../index";
import { IDigitalSignature } from "./digital-signature-base";

export class DigitalSignatureSHA512Wrapper implements IDigitalSignature {
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