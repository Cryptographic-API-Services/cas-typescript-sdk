use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);

/// Converts a `cas-lib` [`CasResult`](cas_lib::error::CasResult) into a
/// [`napi::Result`], turning a [`CasError`](cas_lib::error::CasError) into a JS
/// exception carrying the error's `Display` message. As of `cas-lib` 0.2.79 every
/// fallible cryptographic operation returns a `CasResult` instead of panicking,
/// so each fallible FFI function routes its result through this helper.
pub(crate) fn map_cas_err<T>(result: cas_lib::error::CasResult<T>) -> napi::Result<T> {
    result.map_err(|e| napi::Error::from_reason(e.to_string()))
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