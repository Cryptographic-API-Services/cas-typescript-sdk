import {
  Cased25519KeyPairResult,
  generateEd25519Keys,
  signEd25519,
  verifyEd25519,
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
  public signMessage(privateKey: number[], message: number[]): number[] {
    return signEd25519(privateKey, message);
  }

  /**
   * Verifies a signature for a message with the given Ed25519 public key
   * @param publicKey The public key to verify the signature with
   * @param message The signed message
   * @param signature The signature to verify
   * @returns True if the signature is valid, false otherwise
   */
  public verifyMessage(publicKey: number[], message: number[], signature: number[]): boolean {
    return verifyEd25519(publicKey, message, signature);
  }
}
