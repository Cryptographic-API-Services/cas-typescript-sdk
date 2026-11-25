import { hpkeGenerateKeypair, hpkeEncrypt, hpkeDecrypt, generateInfoStr, HpkeKeyResult, HpkeEncryptResult} from "../../index"


export class HpkeWrapper {

    /**
     * Generate a new HPKE key pair along with a random info string.
     * The random infoStr is not domain separation (see generateInfoString): usually ignore it
     * and pass a fixed, application-specific info to encrypt and decrypt instead.
     * @returns HpkeKeyResult
     */
    
    public generateKeyPair(): HpkeKeyResult {
        return hpkeGenerateKeypair();
    }

    /**
     * Generate 16 random bytes (a UUID v4) to use as an HPKE info string.
     * A random value is not domain separation. info binds the derived keys to a context, so the
     * recipient must pass exactly the same bytes, which means a random value has to be sent or
     * stored alongside the message. Prefer a fixed, application-specific value that both sides
     * already know, such as `new TextEncoder().encode("my-app/v1/file-encryption")`.
     * @returns A byte array representing the info string
     */
    
    public generateInfoString(): number[] {
        return generateInfoStr();
    }

    /**
     * Encrypt a message using HPKE
     * @param plaintext The message to encrypt
     * @param publicKey The recipient's public key
     * @param infoStr Binds the derived keys to a context; the recipient must pass the same bytes.
     * Use a fixed, application-specific value (for example "my-app/v1/file-encryption" as bytes).
     * @param aad Additional authenticated data: authenticated but not encrypted, and not
     * included in the result. The same bytes must be passed to decrypt. Defaults to none.
     * @returns HpkeEncryptResult
     */
    
    public encrypt(plaintext: number[], publicKey: number[], infoStr: number[], aad: number[] = []): HpkeEncryptResult {
        return hpkeEncrypt(plaintext, publicKey, infoStr, aad);
    }

    /**
     * Decrypt a message using HPKE
     * @param ciphertext The encrypted message
     * @param privateKey The recipient's private key
     * @param encapsulatedKey The encapsulated key
     * @param tag The tag
     * @param infoStr The info passed to encrypt. Decryption throws if it does not match.
     * @param aad The additional authenticated data passed to encrypt. Decryption throws if
     * it does not match. Defaults to none.
     * @returns The decrypted message
     */
    
    public decrypt(ciphertext: number[], privateKey: number[], encapsulatedKey: number[], tag: number[], infoStr: number[], aad: number[] = []): number[] {
        return hpkeDecrypt(ciphertext, privateKey, encapsulatedKey, tag, infoStr, aad);
    }
}