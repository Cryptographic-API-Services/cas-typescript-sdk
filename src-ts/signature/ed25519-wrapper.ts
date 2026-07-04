import {
  Cased25519KeyPairResult,
  generateEd25519Keys,
  signEd25519,
  verifyEd25519,
  verifyEd25519WithKeyPair,
} from "../../index";


export class Ed25519Wrapper {
  /**
   * Generates a new Ed25519 key pair
   */
  
  public getKeyPair(): Cased25519KeyPairResult {
    return generateEd25519Keys();
  }

  /**
   * Signs a message with the given Ed25519 private key
   * @param privateKey The private key to sign the message with
   * @param message The message to sign
   * @returns The signature
   */
  
  public signBytes(privateKey: number[], message: number[]): number[] {
    return signEd25519(privateKey, message);
  }

  /**
   * Verifies a signature for a message with the given Ed25519 public key
   * @param publicKey The public key to verify the signature with
   * @param message The signed message
   * @param signature The signature to verify
   * @returns True if the signature is valid, false otherwise
   */
  
  public verifyBytes(publicKey: number[], message: number[], signature: number[]): boolean {
    return verifyEd25519(publicKey, message, signature);
  }

  /**
   * Verifies a signature for a message with the given Ed25519 key pair (the 32 byte private key).
   * Note: this uses non-strict verification, unlike verifyBytes which uses strict
   * verification and rejects some edge-case signatures this method accepts.
   * @param keyPair The 32 byte private key to verify the signature with
   * @param message The signed message
   * @param signature The signature to verify
   * @returns True if the signature is valid, false otherwise
   */

  public verifyWithKeyPairBytes(keyPair: number[], message: number[], signature: number[]): boolean {
    return verifyEd25519WithKeyPair(keyPair, message, signature);
  }
}
