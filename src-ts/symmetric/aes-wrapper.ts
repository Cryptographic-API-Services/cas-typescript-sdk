import {
  AesKeyFromX25519SharedSecret,
  aes128Decrypt,
  aes128Encrypt,
  aes128Key,
  aes128KeyFromX25519SharedSecret,
  aes256Decrypt,
  aes256Encrypt,
  aes256Key,
  aes256KeyFromX25519SharedSecret,
  aesNonce,
} from "../../index";

export class AESWrapper {
    public aes128Key(): Array<number> {
        return aes128Key();
    }

    public aes256Key(): Array<number> {
        return aes256Key();
    }

    public aesNonce(): Array<number> {
        return aesNonce();
    }

    public aes128Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes128Encrypt(aesKey, nonce, plaintext);
    }

    public aes128Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes128Decrypt(aesKey, nonce, ciphertext);
    }

    public aes256Encrypt(aesKey: Array<number>, nonce: Array<number>, plaintext: Array<number>): Array<number> {
        return aes256Encrypt(aesKey, nonce, plaintext);
    }

    public aes256Decrypt(aesKey: Array<number>, nonce: Array<number>, ciphertext: Array<number>): Array<number> {
        return aes256Decrypt(aesKey, nonce, ciphertext);
    }

    public aes256KeyFromX25519SharedSecret(shared_secret: Array<number>): AesKeyFromX25519SharedSecret {
         return aes256KeyFromX25519SharedSecret(shared_secret);
    }

    public aes128KeyFromX25519SharedSecret(shared_secret: Array<number>): AesKeyFromX25519SharedSecret {
        return aes128KeyFromX25519SharedSecret(shared_secret);
   }
}
