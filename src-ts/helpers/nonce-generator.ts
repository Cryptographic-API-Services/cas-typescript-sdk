import * as crypto from "crypto";

export class NonceGenerator {

    /**
     * Generates a unique cryptographic 96-bit nonce for usage with AES-128-GCM and AES-256-GCM.
     * @returns string
     */
    public generateNonce(): string {
        const nonceBytes = crypto.randomBytes(12);
        return nonceBytes.toString('hex').substring(0, 12);
    }
}