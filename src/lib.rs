mod password_hashers {
    pub mod argon2;
    pub mod bcrypt;
    pub mod scrypt;
    pub mod cas_password_hasher;
}

mod hashers {
    pub mod sha;
    pub mod cas_hasher;
    pub mod blake2;
}