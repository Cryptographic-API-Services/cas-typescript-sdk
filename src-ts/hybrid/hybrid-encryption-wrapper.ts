import { RSAWrapper } from "../asymmetric";
import { AESWrapper } from "../symmetric";
import { AesRsaHybridEncryptResult } from "./types/aes-rsa-hybird-encrypt-result";
import { AESRSAHybridInitializer } from "./types/aes-rsa-hybrid-initializer";

export class HybridEncryptionWrapper {
  private aesWrapper: AESWrapper;
  private rsaWrapper: RSAWrapper;

  constructor() {
    this.aesWrapper = new AESWrapper();
    this.rsaWrapper = new RSAWrapper();
  }

  public encryptAESRSAHybrid(
    dataToEncrypt: Array<number>,
    initalizer: AESRSAHybridInitializer,
  ): AesRsaHybridEncryptResult {
    let encryptedData: Array<number> = (initalizer.aesType === 128)
      ? this.aesWrapper.aes128Encrypt(
        initalizer.aesKey,
        initalizer.aesNonce,
        dataToEncrypt,
      )
      : this.aesWrapper.aes256Encrypt(
        initalizer.aesKey,
        initalizer.aesNonce,
        dataToEncrypt,
      );
    let encryptedAesKey: Array<number> = this.rsaWrapper.encrypt(
      initalizer.rsaKeyPair.publicKey,
      initalizer.aesKey,
    );
    let result: AesRsaHybridEncryptResult = new AesRsaHybridEncryptResult(
      encryptedData,
      encryptedAesKey,
      initalizer.aesType,
      initalizer.aesNonce,
    );
    return result;
  }

  public decryptAESRSAHybrid(
    privateKey: string,
    encryptResult: AesRsaHybridEncryptResult,
  ): Array<number> {
    let plaintextAesKey = this.rsaWrapper.decrypt(
      privateKey,
      encryptResult.encryptedAesKey,
    );
    let plaintext = (encryptResult.aesType === 128)
      ? this.aesWrapper.aes128Decrypt(
        plaintextAesKey,
        encryptResult.aesNonce,
        encryptResult.ciphertext,
      )
      : this.aesWrapper.aes256Decrypt(
        plaintextAesKey,
        encryptResult.aesNonce,
        encryptResult.ciphertext,
      );
      return plaintext;
  }
}
