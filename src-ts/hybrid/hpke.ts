import { hpkeGenerateKeypair, hpkeEncrypt, hpkeDecrypt, generateInfoStr, HpkeKeyResult, HpkeEncryptResult} from "../../index"


export class HpkeWrapper {

    /**
     * Generate a new HPKE key pair along with an info string
     * @returns HpkeKeyResult
     */
    
    public generateKeyPair(): HpkeKeyResult {
        return hpkeGenerateKeypair();
    }

    /**
     * Generate a new info string for HPKE
     * @returns A byte array representing the info string
     */
    
    public generateInfoString(): Uint8Array {
        return generateInfoStr();
    }

    /**
     * Encrypt a message using HPKE
     * @param plaintext The message to encrypt
     * @param publicKey The recipient's public key
     * @param infoStr Additional information to include in the encryption
     * @returns HpkeEncryptResult
     */
    
    public encrypt(plaintext: Uint8Array, publicKey: Uint8Array, infoStr: Uint8Array): HpkeEncryptResult {
        return hpkeEncrypt(plaintext, publicKey, infoStr);
    }

    /**
     * Decrypt a message using HPKE
     * @param ciphertext The encrypted message
     * @param privateKey The recipient's private key
     * @param encapsulatedKey The encapsulated key
     * @param tag The tag
     * @param infoStr Additional information to include in the decryption
     * @returns The decrypted message
     */
    
    public decrypt(ciphertext: Uint8Array, privateKey: Uint8Array, encapsulatedKey: Uint8Array, tag: Uint8Array, infoStr: Uint8Array): Uint8Array {
        return hpkeDecrypt(ciphertext, privateKey, encapsulatedKey, tag, infoStr);
    }
}