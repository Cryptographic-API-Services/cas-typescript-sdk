import { scryptHash, scryptHashParams, scryptVerify} from "../../index";
import { IPasswordHasherBase } from "./password-hasher-base";

export class ScryptWrapper implements IPasswordHasherBase {

  /**
   * Hashes a password with SCrypt
   * @param password 
   * @returns string
   */
  public hashPassword(password: string): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Scrypt");
    }
    return scryptHash(password);
  }

  /**
   * Hashes a password with SCrypt using custom parameters
   * @param password 
   * @param cpuCost 
   * @param blockSize 
   * @param parallelism 
   * @returns 
   */
  public hashPasswordParams(password: string, cpuCost: number, blockSize: number, parallelism: number): string {
    if (!password) {
      throw new Error("You must provide a password to hash with Scrypt");
    }
    return scryptHashParams(password, cpuCost, blockSize, parallelism);
  }

  /**
   * Verifies that a password is the same as the hashed password with SCrypt.
   * @param hashedPassword 
   * @param passwordToVerify 
   * @returns boolean
   */
  public verify(hashedPassword: string, passwordToVerify: string): boolean {
    if (!hashedPassword || !passwordToVerify) {
      throw new Error(
        "You must provide a hashed password and a plaintext password to verify with Scrypt",
      );
    }
    return scryptVerify(hashedPassword, passwordToVerify);
  }
}
