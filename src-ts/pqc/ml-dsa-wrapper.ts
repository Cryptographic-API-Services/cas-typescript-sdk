import {
  CasMlDsaKeyPairResult,
  mlDsa65GenerateKeyPair,
  mlDsa65Sign,
  mlDsa65Verify,
} from "../../index";



export class MlDsa65Wrapper {

    /**
     * Generates an ML-DSA-65 (FIPS 204) key pair.
     * The signing key is the 32 byte private seed and the verification key is 1952 bytes.
     * @returns CasMlDsaKeyPairResult
     */

    public generateKeyPair(): CasMlDsaKeyPairResult {
        return mlDsa65GenerateKeyPair();
    }

    /**
     * Signs a message with an ML-DSA-65 signing key (32 byte seed), producing a 3309 byte signature.
     * Uses the deterministic variant of ML-DSA with an empty context string, so signing the
     * same message with the same key always yields the same signature.
     * @param message
     * @param signingKey
     * @returns Array<number>
     */

    public sign(message: Array<number>, signingKey: Array<number>): Array<number> {
        return mlDsa65Sign(message, signingKey);
    }

    /**
     * Verifies an ML-DSA-65 signature (empty context string) with a verification key.
     * Returns false for a signature that does not verify, and throws if the key or
     * signature has the wrong length or the signature is not a valid encoding.
     * @param message
     * @param signature
     * @param verificationKey
     * @returns boolean
     */

    public verify(message: Array<number>, signature: Array<number>, verificationKey: Array<number>): boolean {
        return mlDsa65Verify(message, signature, verificationKey);
    }
}
