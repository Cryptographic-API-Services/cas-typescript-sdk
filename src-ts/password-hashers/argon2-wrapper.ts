import {argon2Hash, argon2Verify} from "./../../index";
import { IPasswordHasherBase, PasswordHasherBase } from "./password-hasher-base";

export class Argon2Wrapper extends PasswordHasherBase implements IPasswordHasherBase {
  public hashPassword(password: string): string {
    if (!password){
      throw new Error("You must provide a password to hash with Argon2");
    }
    return argon2Hash(password);
  }

  public verifyPassword(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error("You must provide a hashed password and a plaintext password to verify with Argon2");
    }
    return argon2Verify(hashedPassword, passwordToVerify);
  }
}
