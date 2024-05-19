use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};
use napi_derive::napi;

use super::types::CASx25519SecretPublicKeyResult;


#[napi]
pub fn x25519_generate_secret_and_public_key() -> CASx25519SecretPublicKeyResult {
    return <X25519 as CASKeyExchange>::generate_secret_and_public_key().into();
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
