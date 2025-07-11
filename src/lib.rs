use zeroizing_alloc::ZeroAlloc;

#[global_allocator]
static ALLOC: ZeroAlloc<std::alloc::System> = ZeroAlloc(std::alloc::System);
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
    mod types;
}

mod asymmetric {
    pub mod cas_rsa;
}

mod digital_signature {
    pub mod sha_512_rsa;
    pub mod sha_256_rsa;
    pub mod sha_512_ed25519;
    pub mod sha_256_ed25519;
    mod types;
}

mod sponges {
    pub mod ascon_aead;
}

mod message {
    pub mod hmac;
}