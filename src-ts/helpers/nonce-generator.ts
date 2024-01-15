import * as crypto from "crypto";

export class NonceGenerator {

    public generateNonce(): string {
        const nonceBytes = crypto.randomBytes(12);
        return nonceBytes.toString('hex').substring(0, 12);
    }
}