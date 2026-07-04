import {
  CasSlhDsaKeyPairResult,
  slhDsaGenerateKeyPair,
  slhDsaSign,
  slhDsaVerify,
} from "../../index";



export class SlhDsaWrapper {

    /**
     * Generates an SLH-DSA (FIPS 205, SHAKE-128f parameter set) key pair.
     * The signing key is 64 bytes and the verification key is 32 bytes.
     * @returns CasSlhDsaKeyPairResult
     */

    public generateKeyPair(): CasSlhDsaKeyPairResult {
        return slhDsaGenerateKeyPair();
    }

    /**
     * Signs a message with an SLH-DSA signing key. Signatures are large (~17 KB)
     * and signing is noticeably slower than the other signature algorithms in this SDK.
     * @param message
     * @param signingKey
     * @returns Array<number>
     */

    public sign(message: Array<number>, signingKey: Array<number>): Array<number> {
        return slhDsaSign(message, signingKey);
    }

    /**
     * Verifies an SLH-DSA signature with a verification key.
     * @param message
     * @param signature
     * @param verificationKey
     * @returns boolean
     */

    public verify(message: Array<number>, signature: Array<number>, verificationKey: Array<number>): boolean {
        return slhDsaVerify(message, signature, verificationKey);
    }
}
