import { scryptHash, scryptVerify } from "../../index";
import { IPasswordHasherBase } from "./password-hasher-base";

export class ScryptWrapper implements IPasswordHasherBase {

    public hashPassword(password: string): string {
        if (!password){
          throw new Error("You must provide a password to hash with Scrypt");
        }
        return scryptHash(password);
      }
    
      public verifyPassword(hashedPassword: string, passwordToVerify: string): boolean {
        if (!hashedPassword || !passwordToVerify) {
          throw new Error("You must provide a hashed password and a plaintext password to verify with Scrypt");
        }
        return scryptVerify(hashedPassword, passwordToVerify);
      }

}