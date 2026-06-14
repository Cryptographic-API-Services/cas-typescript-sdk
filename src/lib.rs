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

mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod scrypt;
}

mod hashers {
    pub mod sha;
    pub mod blake2;
}

mod key_exchange {
    pub mod x25519;
    mod types;
}

mod symmetric {
    pub mod aes;
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