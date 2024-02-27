use napi::bindgen_prelude::ClassInstance;
use napi_derive::napi;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use super::cas_key_exchange::CASKeyExchange;

#[napi(constructor)]
pub struct x25519SecretPublicKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct X25519;

impl CASKeyExchange for X25519 {
    fn generate_secret_and_public_key() -> x25519SecretPublicKeyResult {
        let secret_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&secret_key);
        let result = x25519SecretPublicKeyResult {
            secret_key: secret_key.as_bytes().to_vec(),
            public_key: public_key.as_bytes().to_vec(),
        };
        result
    }

    fn diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> Vec<u8> {
        let mut secret_key_array: [u8; 32] = Default::default();
        secret_key_array.copy_from_slice(&my_secret_key);
        let mut users_public_key_array: [u8; 32] = Default::default();
        users_public_key_array.copy_from_slice(&users_public_key);

        let secret_key = StaticSecret::from(secret_key_array);
        let public_key = PublicKey::from(users_public_key_array);
        return secret_key.diffie_hellman(&public_key).as_bytes().to_vec();
    }
}

#[napi]
pub fn x25519_generate_secret_and_public_key() -> x25519SecretPublicKeyResult {
    return <X25519 as CASKeyExchange>::generate_secret_and_public_key();
}

#[napi]
pub fn x25519_diffie_hellman(my_secret_key: Vec<u8>, users_public_key: Vec<u8>) -> Vec<u8> {
    return <X25519 as CASKeyExchange>::diffie_hellman(my_secret_key, users_public_key);
}

#[test]
pub fn x25519_diffie_hellman_test() {
    let alice = x25519_generate_secret_and_public_key();
    let bob = x25519_generate_secret_and_public_key();

    let alice_shared_secret = x25519_diffie_hellman(alice.secret_key, bob.public_key);
    let bob_shared_secret = x25519_diffie_hellman(bob.secret_key, alice.public_key);
    assert_eq!(true, alice_shared_secret.eq(&bob_shared_secret));
}
