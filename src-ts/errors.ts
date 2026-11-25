/**
 * The stable `code` carried by every error the native cryptography layer throws, one per
 * cas-lib `CasError` variant. Branch on these instead of the message text, which may be reworded.
 *
 * Only errors raised by cas-lib carry one of these codes. Argument checks done by the
 * wrapper classes before calling into native code (for example "Data to compress cannot be
 * null or empty.") throw a plain `Error` with no `code`, so `isCasError` returns `false` for them.
 */
export enum CasErrorCode {
    /** A key had an invalid length or could not be parsed. */
    InvalidKey = "CAS_INVALID_KEY",
    /** A nonce/IV had an invalid length. */
    InvalidNonce = "CAS_INVALID_NONCE",
    /** A signature had an invalid length or could not be parsed. */
    InvalidSignature = "CAS_INVALID_SIGNATURE",
    /** Input bytes could not be decoded into the expected type. */
    InvalidInput = "CAS_INVALID_INPUT",
    /** PEM/DER decoding or encoding of a key failed. */
    InvalidPemKey = "CAS_INVALID_PEM_KEY",
    /** Invalid algorithm parameters, such as a too-small RSA key or out-of-range password-hashing costs. */
    InvalidParameters = "CAS_INVALID_PARAMETERS",
    /** Encryption failed. */
    EncryptionFailed = "CAS_ENCRYPTION_FAILED",
    /** Decryption failed or the authentication tag did not verify (wrong key, nonce, AAD, or tampered data). */
    DecryptionFailed = "CAS_DECRYPTION_FAILED",
    /** A signing operation failed. */
    SigningFailed = "CAS_SIGNING_FAILED",
    /** Key generation failed. */
    KeyGenerationFailed = "CAS_KEY_GENERATION_FAILED",
    /** Password hashing or verification setup failed. */
    PasswordHashingFailed = "CAS_PASSWORD_HASHING_FAILED",
    /** Compression or decompression failed. */
    CompressionFailed = "CAS_COMPRESSION_FAILED",
    /** Decompressed output would exceed the size limit (a possible decompression bomb). */
    DecompressionLimitExceeded = "CAS_DECOMPRESSION_LIMIT_EXCEEDED",
}

/** An `Error` thrown by cas-lib, with its stable `code`. */
export interface CasError extends Error {
    readonly code: CasErrorCode;
}

const CAS_ERROR_CODES: ReadonlySet<unknown> = new Set(Object.values(CasErrorCode));

/**
 * Checks whether `err` was thrown by cas-lib, optionally with a specific `code`.
 * Returns `false` for the plain `Error`s that wrapper classes throw when validating
 * arguments, and for anything that is not an `Error`.
 * @param err the caught value
 * @param code when given, also require this exact code
 * @returns whether `err` is a `CasError` (with `code`, if given)
 */
export function isCasError(err: unknown, code?: CasErrorCode): err is CasError {
    if (!(err instanceof Error)) {
        return false;
    }
    const errCode = (err as { code?: unknown }).code;
    return code === undefined ? CAS_ERROR_CODES.has(errCode) : errCode === code;
}
