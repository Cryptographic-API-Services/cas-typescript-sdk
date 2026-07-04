import {
  CasPbkdf2Result,
  pbkdf2Derive,
  pbkdf2DeriveWithSalt,
} from "../../index";



export class Pbkdf2Wrapper {

    /**
     * Derives a 32 byte key from a password using PBKDF2 with HMAC-SHA3-256.
     * A random salt is generated and returned alongside the derived key so the
     * key can be re-derived later with deriveWithSalt.
     * @param password
     * @param numberOfIterations
     * @returns CasPbkdf2Result
     */

    public derive(password: Array<number>, numberOfIterations: number): CasPbkdf2Result {
        return pbkdf2Derive(password, numberOfIterations);
    }

    /**
     * Derives a 32 byte key from a password and caller-supplied salt using PBKDF2 with HMAC-SHA3-256.
     * Deterministic: the same password, salt, and iteration count always produce the same key.
     * @param password
     * @param numberOfIterations
     * @param salt
     * @returns Array<number>
     */

    public deriveWithSalt(password: Array<number>, numberOfIterations: number, salt: Array<number>): Array<number> {
        return pbkdf2DeriveWithSalt(password, numberOfIterations, salt);
    }
}
