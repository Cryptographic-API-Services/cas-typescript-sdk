import {
  CASPbkdf2Result,
  pbkdf2Derive,
  pbkdf2DeriveWithSalt,
} from "../../index";

const MIN_ITERATIONS = 600_000;
const MIN_SALT_LENGTH = 16;

export class Pbkdf2Wrapper {

    /**
     * Derives a 32 byte key from a password using PBKDF2 with HMAC-SHA3-256.
     * A random salt is generated and returned alongside the derived key so the
     * key can be re-derived later with deriveWithSalt.
     * @param password
     * @param numberOfIterations At least 600,000; fewer throws.
     * @returns CASPbkdf2Result
     */

    public derive(password: Array<number>, numberOfIterations: number): CASPbkdf2Result {
        this.checkIterations(numberOfIterations);
        return pbkdf2Derive(password, numberOfIterations);
    }

    /**
     * Derives a 32 byte key from a password and caller-supplied salt using PBKDF2 with HMAC-SHA3-256.
     * Deterministic: the same password, salt, and iteration count always produce the same key.
     * @param password
     * @param numberOfIterations At least 600,000; fewer throws.
     * @param salt At least 16 bytes; a shorter salt throws.
     * @returns Array<number>
     */

    public deriveWithSalt(password: Array<number>, numberOfIterations: number, salt: Array<number>): Array<number> {
        this.checkIterations(numberOfIterations);
        if (!salt || salt.length < MIN_SALT_LENGTH) {
            throw new Error(`PBKDF2 requires a salt of at least ${MIN_SALT_LENGTH} bytes`);
        }
        return pbkdf2DeriveWithSalt(password, numberOfIterations, salt);
    }

    private checkIterations(numberOfIterations: number): void {
        if (!Number.isInteger(numberOfIterations) || numberOfIterations < MIN_ITERATIONS) {
            throw new Error(`PBKDF2 requires an integer iteration count of at least ${MIN_ITERATIONS}`);
        }
    }
}
