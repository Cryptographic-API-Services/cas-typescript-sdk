import { CASRSAKeyPairResult, generateRsaKeys, signRsa, verifyRsa } from "../../index";


export class RSAWrapper {

  /**
   * Generates an RSA key pair of the given size in bits. 2048, 3072 and 4096 are supported;
   * smaller keys are insecure and cannot be used to sign or verify.
   * @param keySize 2048, 3072 or 4096
   * @returns CASRSAKeyPairResult
   */
  
  public getKeyPair(keySize: number): CASRSAKeyPairResult {
    if (keySize !== 2048 && keySize !== 3072 && keySize !== 4096) {
        throw new Error("RSA key size must be 2048, 3072 or 4096 bits");
    }
    return generateRsaKeys(keySize);
  }

  /**
   * Signs a message with RSASSA-PKCS1-v1_5 and SHA-256 (JWS `RS256`).
   * The message is hashed internally and the signature carries the standard DigestInfo
   * prefix, so it verifies with OpenSSL, WebCrypto, Node's `crypto.verify("sha256", ...)`
   * and other RS256 implementations. Pass the message itself, not a digest of it; it can be any length.
   * Signatures made by 1.x of this SDK are a different format and do not verify, and vice versa.
   * Throws for keys under 2048 bits and for private keys whose two primes differ greatly in size.
   * @param privateKey PKCS#8 PEM private key, as returned by getKeyPair.
   * @param message The message to sign.
   * @returns Array<number>
   */
  
  public sign(privateKey: string, message: Array<number>): Array<number> {
    if (!privateKey) {
      throw new Error("You must provide a private key to sign with RSA");
    }
    if (!message || message.length === 0) {
      throw new Error("You must provide a message to sign with RSA");
    }
    return signRsa(privateKey, message);
  }

  /**
   * Verifies an RSASSA-PKCS1-v1_5 SHA-256 (`RS256`) signature over a message, as produced by
   * sign or any standard RS256 signer. Returns false for a signature that does not match,
   * including signatures made by 1.x of this SDK.
   * Accepts public keys from 2048 up to 8192 bits; smaller keys throw.
   * @param publicKey PKCS#1 PEM public key, as returned by getKeyPair.
   * @param message The message that was signed.
   * @param signature
   * @returns boolean
   */
  
  public verify(publicKey: string, message: Array<number>, signature: Array<number>): boolean {
    if (!publicKey) {
      throw new Error("You must provide a public key to verify with RSA");
    }
    if (!message || message.length === 0) {
      throw new Error("You must provide a message to verify with RSA");
    }
    if (!signature || signature.length === 0) {
      throw new Error("You must provide a signature to verify with RSA");
    }
    return verifyRsa(publicKey, message, signature);
  }
}
