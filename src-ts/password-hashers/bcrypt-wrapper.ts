import { IPasswordHasherBase } from "./password-hasher-base";
import { bcryptHash, bcryptHashParams, bcryptVerify } from "./../../index";

const BCRYPT_MAX_PASSWORD_BYTES = 72;

export class BCryptWrapper implements IPasswordHasherBase {

  /**
   * Hashes a password with BCrypt.
   * The password must be at most 72 bytes of UTF-8 (bytes, not characters);
   * a longer password throws instead of being truncated.
   * @param password 
   * @returns string
   */
  
  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with BCrypt");
    }
    this.checkPasswordLength(password);
    return bcryptHash(password);
  }

  /**
   * Hashes a password with BCrypt using custom cost.
   * The password must be at most 72 bytes of UTF-8 (bytes, not characters);
   * a longer password throws instead of being truncated.
   * @param password 
   * @param cost 
   * @returns 
   */
  
  public hashPasswordWithParameters(password: string, cost: number): string {
    if (!password) {
      throw new Error("You must provide a password to hash with BCrypt");
    }
    this.checkPasswordLength(password);
    return bcryptHashParams(cost, password);
  }

  /**
   * Verifies that a password is the same as the hashed password with BCrypt.
   * A password longer than 72 bytes of UTF-8 throws, since it can never match.
   * @param hashedPassword 
   * @param passwordToVerify 
   * @returns boolean
   */
  
  public verify(
    hashedPassword: string,
    passwordToVerify: string,
  ): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with BCrypt",
      );
    }
    this.checkPasswordLength(passwordToVerify);
    return bcryptVerify(hashedPassword, passwordToVerify);
  }

  private checkPasswordLength(password: string): void {
    const utf8Bytes = Array.from(password).reduce((total, char) => {
      const codePoint = char.codePointAt(0)!;
      return total + (codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4);
    }, 0);
    if (utf8Bytes > BCRYPT_MAX_PASSWORD_BYTES) {
      throw new Error(
        `BCrypt passwords must be at most ${BCRYPT_MAX_PASSWORD_BYTES} bytes of UTF-8`,
      );
    }
  }
}
