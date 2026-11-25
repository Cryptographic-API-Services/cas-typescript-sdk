use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);

use cas_lib::error::CasError;

/// The `code` property of every error this addon throws. napi-rs creates the JS
/// error with its status string as `code`, and its built-in [`napi::Status`] can
/// only say `GenericFailure`, so fallible FFI functions return [`Result`] with
/// this status instead.
///
/// The `CAS_*` strings are public API: `CasErrorCode` in `src-ts/errors.ts`
/// mirrors them, so never rename one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorCode(&'static str);

impl ErrorCode {
    /// napi's own code, for an FFI-side argument check that is not a `CasError`.
    pub const GENERIC_FAILURE: Self = Self("GenericFailure");
}

impl AsRef<str> for ErrorCode {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl From<&CasError> for ErrorCode {
    fn from(error: &CasError) -> Self {
        Self(match error {
            CasError::InvalidKey => "CAS_INVALID_KEY",
            CasError::InvalidNonce => "CAS_INVALID_NONCE",
            CasError::InvalidSignature => "CAS_INVALID_SIGNATURE",
            CasError::InvalidInput => "CAS_INVALID_INPUT",
            CasError::InvalidPemKey => "CAS_INVALID_PEM_KEY",
            CasError::InvalidParameters => "CAS_INVALID_PARAMETERS",
            CasError::EncryptionFailed => "CAS_ENCRYPTION_FAILED",
            CasError::DecryptionFailed => "CAS_DECRYPTION_FAILED",
            CasError::SigningFailed => "CAS_SIGNING_FAILED",
            CasError::KeyGenerationFailed => "CAS_KEY_GENERATION_FAILED",
            CasError::PasswordHashingFailed => "CAS_PASSWORD_HASHING_FAILED",
            CasError::CompressionFailed => "CAS_COMPRESSION_FAILED",
            CasError::DecompressionLimitExceeded => "CAS_DECOMPRESSION_LIMIT_EXCEEDED",
        })
    }
}

/// The return type of every fallible `#[napi]` function. napi-derive only
/// recognises a fallible function by a return type whose last path segment is
/// `Result`, so this alias must keep that name.
pub type Result<T> = napi::Result<T, ErrorCode>;

/// Converts a `cas-lib` [`CasResult`](cas_lib::error::CasResult) into a
/// [`Result`], turning a [`CasError`] into a JS exception whose `code` is the
/// error's [`ErrorCode`] and whose message is its `Display` text. As of `cas-lib`
/// 0.2.79 every fallible cryptographic operation returns a `CasResult` instead of
/// panicking, so each fallible FFI function routes its result through this helper.
pub(crate) fn map_cas_err<T>(result: cas_lib::error::CasResult<T>) -> Result<T> {
    result.map_err(|e| napi::Error::new(ErrorCode::from(&e), e.to_string()))
}

#[cfg(test)]
mod error_code_tests {
    use super::ErrorCode;
    use cas_lib::error::CasError;

    /// Every `CasError` variant, in `error_code()` order. The exhaustive `match`
    /// in `From<&CasError> for ErrorCode` fails to compile on a new variant; this
    /// list is checked against the dense 1..=N numeric codes so it can't fall behind.
    const ALL_VARIANTS: [CasError; 13] = [
        CasError::InvalidKey,
        CasError::InvalidNonce,
        CasError::InvalidSignature,
        CasError::InvalidInput,
        CasError::InvalidPemKey,
        CasError::InvalidParameters,
        CasError::EncryptionFailed,
        CasError::DecryptionFailed,
        CasError::SigningFailed,
        CasError::KeyGenerationFailed,
        CasError::PasswordHashingFailed,
        CasError::CompressionFailed,
        CasError::DecompressionLimitExceeded,
    ];

    #[test]
    fn every_cas_error_maps_to_a_distinct_code() {
        let numeric: Vec<i32> = ALL_VARIANTS.iter().map(CasError::error_code).collect();
        assert_eq!((1..=ALL_VARIANTS.len() as i32).collect::<Vec<_>>(), numeric);

        let mut codes: Vec<&str> = ALL_VARIANTS
            .iter()
            .map(|e| ErrorCode::from(e).0)
            .collect();
        assert!(codes.iter().all(|code| code.starts_with("CAS_")));
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(ALL_VARIANTS.len(), codes.len());
    }

    #[test]
    fn every_code_is_in_the_typescript_enum() {
        let errors_ts = include_str!("../src-ts/errors.ts");
        for error in &ALL_VARIANTS {
            let code = ErrorCode::from(error).0;
            let member = format!("{error:?} = \"{code}\"");
            assert!(
                errors_ts.contains(&member),
                "`{member}` is missing from CasErrorCode in src-ts/errors.ts"
            );
        }
    }

    #[test]
    fn map_cas_err_keeps_the_display_message() {
        let err = super::map_cas_err::<()>(Err(CasError::DecryptionFailed)).unwrap_err();
        assert_eq!("CAS_DECRYPTION_FAILED", err.status.as_ref());
        assert_eq!(CasError::DecryptionFailed.to_string(), err.reason);
    }
}

/// Test-only inputs generated at runtime, so the inline `#[test]` functions never
/// feed a hard-coded literal into a password or nonce parameter (which CodeQL's
/// `rust/hard-coded-cryptographic-value` query reports, even in test code).
#[cfg(test)]
pub(crate) mod test_util {
    /// A fresh random 32-character password (hex of 16 CSPRNG bytes).
    pub fn random_password() -> String {
        crate::symmetric::aes::aes128_key()
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}

mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod pbkdf2;
    pub mod scrypt;
}

mod hashers {
    pub mod sha;
    pub mod sha2;
    pub mod blake2;
}

mod key_exchange {
    pub mod x25519;
    mod types;
}

mod symmetric {
    pub mod aes;
    pub mod aes_gcm_siv;
    pub mod chacha20poly1305;
}

mod pqc {
    pub mod ml_dsa;
    pub mod ml_kem;
    pub mod slh_dsa;
}

mod asymmetric {
    pub mod cas_rsa;
    pub mod cas_ed25519;
}

mod sponges {
    pub mod ascon_aead;
}

mod message {
    pub mod hmac;
}

mod hybrid {
    pub mod hpke;
    pub mod types;
}

pub mod compression;