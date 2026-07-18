import { Argon2Wrapper } from "./argon2-wrapper";
import { BCryptWrapper } from "./bcrypt-wrapper";
import { IPasswordHasherBase } from "./password-hasher-base";
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
    let hasher: IPasswordHasherBase | null = null;
    switch (type) {
      case PasswordHasherType.Bcrypt:
        hasher = new BCryptWrapper();
        break;
      case PasswordHasherType.Scrypt:
        hasher = new ScryptWrapper();
        break;
      case PasswordHasherType.Argon2:
        hasher = new Argon2Wrapper();
        break;
    }

    if (!hasher) {
      throw new Error(`Password hasher type ${type} is not supported.`);
    }

    return hasher;
  }
}
