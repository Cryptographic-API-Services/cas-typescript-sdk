import { CASx25519SecretPublicKeyResult, x25519DiffieHellman, x25519GenerateSecretAndPublicKey } from "../../index"


export class X25519Wrapper {
    /**
     * Generates and secret and public key to be used to create a shared secret with Diffie Hellman.
     * User should share their public key with the other user and take the other user's public key and they can generate a Shared Secret.
     * @returns X25519SecretPublicKeyResult
     */
    
    public generateSecretAndPublicKey(): CASx25519SecretPublicKeyResult {
        return x25519GenerateSecretAndPublicKey();
    }

    /**
     * User takes their secret key and the other user's public key to generate a shared secret.
     * Don't use the shared secret as a key directly: derive one with the X25519 key-derivation
     * method of the cipher you'll use, passing both public keys.
     * Throws if either key is not 32 bytes or if the peer's public key is a low-order point,
     * which would force an all-zero shared secret an attacker knows.
     * @param secretKey 
     * @param publicKey 
     * @returns Array<number>
     */
    
    public generateSharedSecret(secretKey: Array<number>, publicKey: Array<number>): Array<number> {
        return x25519DiffieHellman(secretKey, publicKey);
    }
}