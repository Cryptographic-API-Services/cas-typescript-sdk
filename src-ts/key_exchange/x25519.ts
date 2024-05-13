import { x25519DiffieHellman, x25519GenerateSecretAndPublicKey, X25519SecretPublicKeyResult } from "../../index"

export class X25519Wrapper {
    /**
     * Generates and secret and public key to be used to create a shared secret with Diffie Hellman.
     * User should share their public key with the other user and take the other user's public key and they can generate a Shared Secret.
     * @returns X25519SecretPublicKeyResult
     */
    public generateSecretAndPublicKey(): X25519SecretPublicKeyResult {
        return x25519GenerateSecretAndPublicKey();
    }

    /**
     * User takes their secret key and the other user's public key to generate a shared secret.
     * Can be used to derive an AES key over insecure channel.
     * @param secretKey 
     * @param publicKey 
     * @returns Array<number>
     */
    public generateSharedSecret(secretKey: Array<number>, publicKey: Array<number>): Array<number> {
        return x25519DiffieHellman(secretKey, publicKey);
    }
}