mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod cas_password_hasher;
    pub mod scrypt;
}

mod hashers {
    pub mod blake2;
    pub mod cas_hasher;
    pub mod sha;
}

mod key_exchange {
    pub mod cas_key_exchange;
    pub mod x25519;
}

mod symmetric {
    pub mod aes;
    pub mod cas_symmetric_encryption;
}

mod asymmetric {
    pub mod cas_asymmetric_encryption;
    pub mod cas_rsa;
}

mod digital_signature {
    pub mod cas_digital_signature_rsa;
    pub mod sha_512_rsa;
    pub mod sha_256_rsa;
    pub mod sha_512_ed25519;
    pub mod sha_256_ed25519;
}

mod sponges {
    pub mod cas_ascon_aead;
    pub mod ascon_aead;
}