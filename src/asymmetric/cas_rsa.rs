use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};
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
pub fn sign_rsa(private_key: String, hash: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(CASRSA::sign(private_key, hash))
}

#[napi]
pub fn verify_rsa(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> napi::Result<bool> {
    crate::map_cas_err(CASRSA::verify(public_key, hash, signature))
}
