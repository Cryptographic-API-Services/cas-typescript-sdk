import { CasrsaDigitalSignatureResult, sha256RsaDigitalSignature, sha256RsaVerifyDigitalSignature } from "../../index";
import { IDigitalSignature } from "./digital-signature-base";

export class DigitalSignatureSHA256Wrapper implements IDigitalSignature {

    createRsa(rsa_key_size: number, data_to_sign: number[]): CasrsaDigitalSignatureResult {
        if (rsa_key_size !== 1024 && rsa_key_size !== 2048 && rsa_key_size !== 4096) {
            throw new Error("You need to provide an appropriate RSA key size.");
        }
        if (data_to_sign?.length === 0) {
            throw new Error("Must provide allocated data to sign");
        }
        return sha256RsaDigitalSignature(rsa_key_size, data_to_sign);
    }
    
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
        return sha256RsaVerifyDigitalSignature(public_key, data_to_verify, signature);
    }
}