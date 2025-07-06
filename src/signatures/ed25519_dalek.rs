use cas_lib::signatures::{cas_ed25519::Ed25519ByteSignature, ed25519::{get_ed25519_key_pair, get_ed25519_key_pair_threadpool}};
use napi_derive::napi;

#[napi]
pub fn ed25519_dalek_generate_keypair() -> Vec<u8> {
    return get_ed25519_key_pair().to_vec();
}

#[napi]
pub fn ed25519_dalek_generate_keypair_threadpool() -> Vec<u8> {
    return get_ed25519_key_pair_threadpool().to_vec();
}