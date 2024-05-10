import { x25519DiffieHellman, x25519GenerateSecretAndPublicKey, X25519SecretPublicKeyResult } from "../../index"

export class X25519Wrapper {
    public generateSecretAndPublicKey(): X25519SecretPublicKeyResult {
        return x25519GenerateSecretAndPublicKey();
    }

    public generateSharedSecret(secretKey: Array<number>, publicKey: Array<number>) {
        return x25519DiffieHellman(secretKey, publicKey);
    }
}