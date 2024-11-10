import { CASRSAKeyPairResult, generateRsaKeys, signRsa, verifyRsa } from "../../index";

export class RSAWrapper {

  /**
   * Generates an RSA key pair based of parameter sent in 1024, 2048, and 4096 are supported.
   * @param keySize 
   * @returns CASRSAKeyPairResult
   */
  public generateKeys(keySize: number): CASRSAKeyPairResult {
    if (keySize !== 1024 && keySize !== 2048 && keySize !== 4096) {
        throw new Error("You must provide an appropriate key size to generate RSA keys");
    }
    return generateRsaKeys(keySize);
  }

  /**
   * Encrypts a plaintext byte array with a RSA public key
   * @param publicKey 
   * @param plaintext 
   * @returns Array<number>
   */

  /**
   * Signs a byte array with an RSA private key for verification.
   * @param privateKey 
   * @param hash 
   * @returns Array<number>
   */
  public sign(privateKey: string, dataToSign: Array<number>): Array<number> {
    if (!privateKey) {
      throw new Error("You must provide a private key to sign with RSA");
    }
    if (!dataToSign || dataToSign.length === 0) {
      throw new Error("You must provide an allocated hash to sign with RSA");
    }
    return signRsa(privateKey, dataToSign);
  }

  /**
   * Verifies signed data by the corresponding private key with an RSA public key.
   * @param publicKey 
   * @param hash 
   * @param signature 
   * @returns boolean
   */
  public verify(publicKey: string, hash: Array<number>, signature: Array<number>): boolean {
    if (!publicKey) {
      throw new Error("You must provide a public key to verify with RSA");
    }
    if (!hash || hash.length === 0) {
      throw new Error("You must provide an allocated hash to verify with RSA");
    }
    if (!signature || signature.length === 0) {
      throw new Error("You must provide and allocated signature to verify with RSA");
    }
    return verifyRsa(publicKey, hash, signature);
  }
}
