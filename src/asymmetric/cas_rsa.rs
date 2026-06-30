use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi(constructor)]
pub struct CASRSAKeyPairResult {
    pub private_key: String,
    pub public_key: String,
}

impl From<RSAKeyPairResult> for CASRSAKeyPairResult {
    fn from(result: RSAKeyPairResult) -> Self {
        CASRSAKeyPairResult {
            private_key: result.private_key,
            public_key: result.public_key,
        }
    }
}

#[napi]
pub fn generate_rsa_keys(key_size: u32) -> napi::Result<CASRSAKeyPairResult> {
    Ok(crate::map_cas_err(CASRSA::generate_rsa_keys(key_size as usize))?.into())
}

#[napi]
pub fn sign_rsa(private_key: String, hash: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(CASRSA::sign(private_key, hash.to_vec())).map(Uint8Array::from)
}

#[napi]
pub fn verify_rsa(public_key: String, hash: Uint8Array, signature: Uint8Array) -> napi::Result<bool> {
    crate::map_cas_err(CASRSA::verify(public_key, hash.to_vec(), signature.to_vec()))
}

#[test]
fn rsa_sign_verify_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let hash = "NotMyDataToHash".as_bytes().to_vec();
    let signature = sign_rsa(key_pair.private_key, hash.clone().into()).unwrap();
    let verified = verify_rsa(key_pair.public_key, hash.into(), signature).unwrap();
    assert_eq!(true, verified);
}

#[test]
fn rsa_verify_fail_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let hash = "NotMyDataToHash".as_bytes().to_vec();
    let signature = sign_rsa(key_pair.private_key, hash.into()).unwrap();
    let tampered_hash = "NotMyDataToHash2".as_bytes().to_vec();
    let verified = verify_rsa(key_pair.public_key, tampered_hash.into(), signature).unwrap();
    assert_eq!(false, verified);
}
