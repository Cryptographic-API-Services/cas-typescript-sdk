
use cas_lib::signatures::cas_ed25519::Ed25519ByteKeyPair;
use cas_lib::signatures::ed25519::{get_ed25519_key_pair, ed25519_sign_with_key_pair, ed25519_verify_with_public_key};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi(constructor)]
pub struct CASED25519KeyPairResult {
    pub private_key: Uint8Array,
    pub public_key: Uint8Array,
}

impl From<Ed25519ByteKeyPair> for CASED25519KeyPairResult {
    fn from(result: Ed25519ByteKeyPair) -> Self {
        CASED25519KeyPairResult {
            private_key: result.key_pair.into(),
            public_key: result.public_key.into()
        }
    }
}

#[napi]
pub fn generate_ed25519_keys() -> CASED25519KeyPairResult {
    return get_ed25519_key_pair().into();
}

#[napi]
pub fn sign_ed25519(private_key: Uint8Array, message: Uint8Array) -> napi::Result<Uint8Array> {
    let signature = crate::map_cas_err(ed25519_sign_with_key_pair(private_key.to_vec(), message.to_vec()))?;
    Ok(signature.signature.into()) // Ed25519ByteSignature has a field named `signature: Vec<u8>`
}

#[napi]
pub fn verify_ed25519(public_key: Uint8Array, message: Uint8Array, signature: Uint8Array) -> napi::Result<bool> {
    crate::map_cas_err(ed25519_verify_with_public_key(public_key.to_vec(), signature.to_vec(), message.to_vec()))
}

#[test]
fn ed25519_sign_verify_test() {
    let key_pair = generate_ed25519_keys();
    let message = "NotMyDataToHash".as_bytes().to_vec();
    let signature = sign_ed25519(key_pair.private_key, message.clone().into()).unwrap();
    let verified = verify_ed25519(key_pair.public_key, message.into(), signature).unwrap();
    assert_eq!(true, verified);
}

#[test]
fn ed25519_verify_fail_test() {
    let key_pair = generate_ed25519_keys();
    let message = "NotMyDataToHash".as_bytes().to_vec();
    let signature = sign_ed25519(key_pair.private_key, message.into()).unwrap();
    let tampered_message = "NotMyDataToHash2".as_bytes().to_vec();
    let verified = verify_ed25519(key_pair.public_key, tampered_message.into(), signature).unwrap();
    assert_eq!(false, verified);
}
