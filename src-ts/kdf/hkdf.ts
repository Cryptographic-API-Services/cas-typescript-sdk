import {
    hkdfSha256Derive,
    hkdfSha256Expand,
    hkdfSha256Extract,
    hkdfSha512Derive,
    hkdfSha512Expand,
    hkdfSha512Extract,
} from "../../index";

/** Rejects lengths the native `u32` argument would silently truncate or wrap. */
function checkLength(length: number): number {
    if (!Number.isInteger(length) || length < 0 || length > 0xffffffff) {
        throw new Error("length must be a non-negative integer");
    }
    return length;
}

/**
 * HKDF (RFC 5869) with HMAC-SHA-256 or HMAC-SHA-512.
 *
 * Use it to turn a shared secret (X25519, ML-KEM, or several concatenated) into keys.
 * It is not a password hash: use {@link Argon2Wrapper} for passwords.
 *
 * - `extract` condenses input keying material and an optional salt into a pseudorandom
 *   key (PRK): 32 bytes for SHA-256, 64 for SHA-512.
 * - `expand` derives `length` bytes from a PRK for the purpose named by `info`. Expanding
 *   one PRK with distinct `info` values gives unrelated keys.
 * - `derive` is `extract` followed by one `expand`.
 *
 * An empty, `null` or `undefined` salt means "no salt" (a salt of hash-length zero bytes).
 * `expand` and `derive` throw a `CasError` with code `CAS_INVALID_PARAMETERS` if `length`
 * is 0 or above 255 × hash length (8160 bytes for SHA-256, 16320 for SHA-512), and
 * `expand` throws `CAS_INVALID_KEY` if the PRK is shorter than the hash length.
 */
export class HkdfWrapper {
    /**
     * HKDF-Extract with HMAC-SHA-256.
     * @param salt Optional, non-secret salt
     * @param ikm The input keying material
     * @returns The 32-byte pseudorandom key
     */
    public hkdfSha256Extract(salt: Array<number> | null | undefined, ikm: Array<number>): Array<number> {
        return hkdfSha256Extract(salt ?? [], ikm);
    }

    /**
     * HKDF-Expand with HMAC-SHA-256.
     * @param prk A pseudorandom key of at least 32 bytes, e.g. from `hkdfSha256Extract`
     * @param info Context naming what the key is for (may be empty)
     * @param length Output length in bytes, 1 to 8160
     * @returns `length` bytes of output keying material
     */
    public hkdfSha256Expand(prk: Array<number>, info: Array<number> | null | undefined, length: number): Array<number> {
        return hkdfSha256Expand(prk, info ?? [], checkLength(length));
    }

    /**
     * HKDF-Extract then HKDF-Expand with HMAC-SHA-256.
     * @param salt Optional, non-secret salt
     * @param ikm The input keying material
     * @param info Context naming what the key is for (may be empty)
     * @param length Output length in bytes, 1 to 8160
     * @returns `length` bytes of output keying material
     */
    public hkdfSha256Derive(
        salt: Array<number> | null | undefined,
        ikm: Array<number>,
        info: Array<number> | null | undefined,
        length: number,
    ): Array<number> {
        return hkdfSha256Derive(salt ?? [], ikm, info ?? [], checkLength(length));
    }

    /**
     * HKDF-Extract with HMAC-SHA-512.
     * @param salt Optional, non-secret salt
     * @param ikm The input keying material
     * @returns The 64-byte pseudorandom key
     */
    public hkdfSha512Extract(salt: Array<number> | null | undefined, ikm: Array<number>): Array<number> {
        return hkdfSha512Extract(salt ?? [], ikm);
    }

    /**
     * HKDF-Expand with HMAC-SHA-512.
     * @param prk A pseudorandom key of at least 64 bytes, e.g. from `hkdfSha512Extract`
     * @param info Context naming what the key is for (may be empty)
     * @param length Output length in bytes, 1 to 16320
     * @returns `length` bytes of output keying material
     */
    public hkdfSha512Expand(prk: Array<number>, info: Array<number> | null | undefined, length: number): Array<number> {
        return hkdfSha512Expand(prk, info ?? [], checkLength(length));
    }

    /**
     * HKDF-Extract then HKDF-Expand with HMAC-SHA-512.
     * @param salt Optional, non-secret salt
     * @param ikm The input keying material
     * @param info Context naming what the key is for (may be empty)
     * @param length Output length in bytes, 1 to 16320
     * @returns `length` bytes of output keying material
     */
    public hkdfSha512Derive(
        salt: Array<number> | null | undefined,
        ikm: Array<number>,
        info: Array<number> | null | undefined,
        length: number,
    ): Array<number> {
        return hkdfSha512Derive(salt ?? [], ikm, info ?? [], checkLength(length));
    }
}
