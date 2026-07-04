import {
  CasMlKemEncapResult,
  CasMlKemKeyPairResult,
  mlKem1024Decapsulate,
  mlKem1024Encapsulate,
  mlKem1024GenerateKeyPair,
} from "../../index";



export class MlKem1024Wrapper {

    /**
     * Generates an ML-KEM-1024 (FIPS 203) key pair.
     * The secret (decapsulation) key is 3168 bytes and the public (encapsulation) key is 1568 bytes.
     * @returns CasMlKemKeyPairResult
     */

    public generateKeyPair(): CasMlKemKeyPairResult {
        return mlKem1024GenerateKeyPair();
    }

    /**
     * Encapsulates to a public key, producing a 1568 byte ciphertext and a 32 byte shared secret.
     * @param publicKey
     * @returns CasMlKemEncapResult
     */

    public encapsulate(publicKey: Array<number>): CasMlKemEncapResult {
        return mlKem1024Encapsulate(publicKey);
    }

    /**
     * Decapsulates a ciphertext with the secret key, recovering the 32 byte shared secret.
     * @param secretKey
     * @param ciphertext
     * @returns Array<number>
     */

    public decapsulate(secretKey: Array<number>, ciphertext: Array<number>): Array<number> {
        return mlKem1024Decapsulate(secretKey, ciphertext);
    }
}
