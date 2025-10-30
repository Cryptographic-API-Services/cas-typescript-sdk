
use cas_lib::signatures::cas_ed25519::{Ed25519ByteKeyPair, Ed25519ByteSignature};
use cas_lib::signatures::ed25519::{get_ed25519_key_pair, ed25519_sign_with_key_pair, ed25519_verify_with_public_key};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASED25519KeyPairResult {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<Ed25519ByteKeyPair> for CASED25519KeyPairResult {
    fn from(result: Ed25519ByteKeyPair) -> Self {
        CASED25519KeyPairResult {
            private_key: result.key_pair,
            public_key: result.public_key
        }
    }
}

#[napi]
pub fn generate_ed25519_keys() -> CASED25519KeyPairResult {
    return get_ed25519_key_pair().into();
}

#[napi]
pub fn sign_ed25519(private_key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    let signature = ed25519_sign_with_key_pair(private_key, message);
    signature.signature // assuming Ed25519ByteSignature has a field named `signature: Vec<u8>`
}

#[napi]
pub fn verify_ed25519(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    return ed25519_verify_with_public_key(public_key, signature, message);
}
