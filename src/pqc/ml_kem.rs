use cas_lib::pqc::cas_pqc::{MlKemEncapResult, MlKemKeyPair};
use cas_lib::pqc::ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASMlKemKeyPairResult {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl From<MlKemKeyPair> for CASMlKemKeyPairResult {
    fn from(result: MlKemKeyPair) -> Self {
        CASMlKemKeyPairResult {
            secret_key: result.secret_key,
            public_key: result.public_key,
        }
    }
}

#[napi(constructor)]
pub struct CASMlKemEncapResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<MlKemEncapResult> for CASMlKemEncapResult {
    fn from(result: MlKemEncapResult) -> Self {
        CASMlKemEncapResult {
            ciphertext: result.ciphertext,
            shared_secret: result.shared_secret,
        }
    }
}

#[napi]
pub fn ml_kem1024_generate_key_pair() -> CASMlKemKeyPairResult {
    return ml_kem_1024_generate().into();
}

#[napi]
pub fn ml_kem1024_encapsulate(public_key: Vec<u8>) -> napi::Result<CASMlKemEncapResult> {
    Ok(crate::map_cas_err(ml_kem_1024_encapsulate(public_key))?.into())
}

#[napi]
pub fn ml_kem1024_decapsulate(secret_key: Vec<u8>, ciphertext: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(ml_kem_1024_decapsulate(secret_key, ciphertext))
}

#[test]
fn ml_kem1024_encapsulate_decapsulate_test() {
    let key_pair = ml_kem1024_generate_key_pair();
    let encap = ml_kem1024_encapsulate(key_pair.public_key).unwrap();
    let shared_secret = ml_kem1024_decapsulate(key_pair.secret_key, encap.ciphertext).unwrap();
    assert_eq!(shared_secret, encap.shared_secret);
}

#[test]
fn ml_kem1024_rejects_bad_lengths_test() {
    let key_pair = ml_kem1024_generate_key_pair();
    assert!(ml_kem1024_encapsulate(vec![0u8; 10]).is_err());
    assert!(ml_kem1024_decapsulate(key_pair.secret_key, vec![0u8; 10]).is_err());
}
