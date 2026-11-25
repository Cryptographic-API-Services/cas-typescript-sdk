import {
  aes128Decrypt,
  aes128Encrypt,
  aes128Key,
  aes128KeyFromVec,
  aes128KeyFromX25519SharedSecret,
  aes128Open,
  aes128Seal,
  aes256Decrypt,
  aes256Encrypt,
  aes256Key,
  aes256KeyFromVec,
  aes256KeyFromX25519SharedSecret,
  aes256Open,
  aes256Seal,
  aesNonce,
} from "../../index";



export class AESWrapper {

    /**
     * Encrypts with AES-128-GCM under a fresh random 96 bit nonce and returns
     * `nonce (12 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
     * nonce is generated for you, so it cannot be reused by mistake.
     * A random 96 bit nonce is only safe for about 2^32 messages per key, so rotate keys
     * well before that. If you have to manage nonces yourself, use AESGCMSIVWrapper,
     * which tolerates nonce reuse.
     * @param aesKey 16 byte key from aes128Key()
     * @param plaintext
     * @param aad optional additional authenticated data: not encrypted or stored in the
     * output, but the same bytes must be passed to aes128Open. Omitting it is the same as empty AAD.
     * @returns Array<number>
     */

    public aes128Seal(aesKey: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
        return aes128Seal(aesKey, plaintext, aad);
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob produced by aes128Seal.
     * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
     * shorter than nonce + tag (28 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
     * tag or AAD do not authenticate.
     * @param aesKey the key passed to aes128Seal
     * @param sealed output of aes128Seal
     * @param aad the AAD passed to aes128Seal, if any
     * @returns Array<number>
     */

    public aes128Open(aesKey: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
        return aes128Open(aesKey, sealed, aad);
    }

    /**
     * Encrypts with AES-256-GCM under a fresh random 96 bit nonce and returns
     * `nonce (12 bytes) || ciphertext || tag (16 bytes)`. This is the recommended API: the
     * nonce is generated for you, so it cannot be reused by mistake.
     * A random 96 bit nonce is only safe for about 2^32 messages per key, so rotate keys
     * well before that. If you have to manage nonces yourself, use AESGCMSIVWrapper,
     * which tolerates nonce reuse.
     * @param aesKey 32 byte key from aes256Key()
     * @param plaintext
     * @param aad optional additional authenticated data: not encrypted or stored in the
     * output, but the same bytes must be passed to aes256Open. Omitting it is the same as empty AAD.
     * @returns Array<number>
     */

    public aes256Seal(aesKey: Array<number>, plaintext: Array<number>, aad?: Array<number>): Array<number> {
        return aes256Seal(aesKey, plaintext, aad);
    }

    /**
     * Decrypts a `nonce || ciphertext || tag` blob produced by aes256Seal.
     * Throws CAS_INVALID_KEY for a key of the wrong length, CAS_INVALID_INPUT for a blob
     * shorter than nonce + tag (28 bytes), and CAS_DECRYPTION_FAILED if the key, ciphertext,
     * tag or AAD do not authenticate.
     * @param aesKey the key passed to aes256Seal
     * @param sealed output of aes256Seal
     * @param aad the AAD passed to aes256Seal, if any
     * @returns Array<number>
     */

    public aes256Open(aesKey: Array<number>, sealed: Array<number>, aad?: Array<number>): Array<number> {
        return aes256Open(aesKey, sealed, aad);
    }

    /**
     * @description Generates a 128 bit AES key
     * @returns returns a 128 bit AES key
     */
    
    public aes128Key(): Array<number> {
        return aes128Key();
    }

    /**
     * @description Generates a 256 bit AES key
     * @returns returns a 256 bit AES key
     */
    
    public aes256Key(): Array<number> {
        return aes256Key();
    }

    /**
     * Generates an 96 bit AES nonce
     * @returns Array<number>
     */
    
    public generateAESNonce(): Array<number> {
        return aesNonce();
    }

    /**
     * Encrypts with AES 128 under a caller-supplied nonce. Never reuse a nonce with the same
     * key: that reveals the XOR of the plaintexts and lets an attacker forge messages.
     * Prefer aes128Seal, which generates the nonce for you.
     * @param aesKey 
     * @param nonce 
     * @param plaintext 
     * @returns Array<number>
     */
    
    public aes128Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes128Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 128
     * @param aesKey 
     * @param nonce 
     * @param ciphertext 
     * @returns Array<number>
     */
    
    public aes128Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes128Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Encrypts with AES-256 under a caller-supplied nonce. Never reuse a nonce with the same
     * key: that reveals the XOR of the plaintexts and lets an attacker forge messages.
     * Prefer aes256Seal, which generates the nonce for you.
     * @param aesKey 
     * @param nonce 
     * @param plaintext 
     * @returns 
     */
    
    public aes256Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes256Encrypt(aesKey, nonce, plaintext);
    }

    /**
     * Decrypts with AES 256
     * @param aesKey 
     * @param nonce 
     * @param ciphertext 
     * @returns 
     */
    
    public aes256Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes256Decrypt(aesKey, nonce, ciphertext);
    }

    /**
     * Derives a 32 byte AES-256-GCM key from a X25519 Diffie Hellman shared secret with HKDF-SHA256.
     * The key is bound to AES-256-GCM and to both parties' public keys, so the same shared
     * secret gives unrelated keys for other ciphers, and both peers derive the same key only
     * if they saw the same public keys. Pass the public keys in either order.
     * Keys differ from those derived by earlier versions of this SDK: both peers must upgrade together.
     * Throws if any input is not 32 bytes or the shared secret is all zeros.
     * @param sharedSecret Output of X25519Wrapper.generateSharedSecret.
     * @param publicKeyA One party's 32 byte X25519 public key.
     * @param publicKeyB The other party's 32 byte X25519 public key.
     * @returns Array<number>
     */
    
    public aes256KeyNonceX25519DiffieHellman(sharedSecret: Array<number>, publicKeyA: Array<number>, publicKeyB: Array<number>): number[] {
         return aes256KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB);
    }

    /**
     * Derives a 16 byte AES-128-GCM key from a X25519 Diffie Hellman shared secret with HKDF-SHA256.
     * The key is bound to AES-128-GCM and to both parties' public keys, so the same shared
     * secret gives unrelated keys for other ciphers, and both peers derive the same key only
     * if they saw the same public keys. Pass the public keys in either order.
     * Keys differ from those derived by earlier versions of this SDK: both peers must upgrade together.
     * Throws if any input is not 32 bytes or the shared secret is all zeros.
     * @param sharedSecret Output of X25519Wrapper.generateSharedSecret.
     * @param publicKeyA One party's 32 byte X25519 public key.
     * @param publicKeyB The other party's 32 byte X25519 public key.
     * @returns Array<number>
     */
    
    public aes128KeyNonceX25519DiffieHellman(sharedSecret: Array<number>, publicKeyA: Array<number>, publicKeyB: Array<number>): number[] {
        return aes128KeyFromX25519SharedSecret(sharedSecret, publicKeyA, publicKeyB);
   }

    /**
     * Validates a caller-supplied 16 byte AES-128 key. Throws if the length is wrong.
     * @param key
     * @returns Array<number>
     */

    public aes128KeyFromBytes(key: Array<number>): Array<number> {
        return aes128KeyFromVec(key);
    }

    /**
     * Validates a caller-supplied 32 byte AES-256 key. Throws if the length is wrong.
     * @param key
     * @returns Array<number>
     */

    public aes256KeyFromBytes(key: Array<number>): Array<number> {
        return aes256KeyFromVec(key);
    }
}
