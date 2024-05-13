import { Argon2Wrapper } from "./argon2-wrapper";
import { BCryptWrapper } from "./bcrypt-wrapper";
import { PasswordHasherType } from "./password-hasher-type";
import { ScryptWrapper } from "./scrypt-wrapper";

export class PasswordHasherFactory {
  /**
   * Returns the appropriate hasher type based upon the type passed in.
   * @param type 
   * @returns 
   */
  static getHasher(type: PasswordHasherType): any {
    // Argon2 by default
    let hasher = new Argon2Wrapper();
    switch (type) {
      case PasswordHasherType.Bcrypt:
        hasher = new BCryptWrapper();
        break;
      case PasswordHasherType.Scrypt:
        hasher = new ScryptWrapper();
        break;
    }
    return hasher;
  }
}
