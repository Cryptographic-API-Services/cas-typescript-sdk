import { Argon2Wrapper } from "./argon2-wrapper";
import { BCryptWrapper } from "./bcrypt-wrapper";
import { PasswordHasherType } from "./password-hasher-type";

export class PasswordHasherFactory {
  static getHasher(type: PasswordHasherType): any {
    // Argon2 by default
    let hasher = new Argon2Wrapper();
    switch (type) {
      case PasswordHasherType.Bcrypt:
        hasher = new BCryptWrapper();
        break;
      case PasswordHasherType.Scrypt:
        break;
    }
    return hasher;
  }
}
