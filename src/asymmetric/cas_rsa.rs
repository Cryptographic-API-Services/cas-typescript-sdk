use cas_lib::asymmetric::{cas_asymmetric_encryption::{CASRSAEncryption, RSAKeyPairResult}, cas_rsa::CASRSA};
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
pub fn generate_rsa_keys(key_size: u32) -> CASRSAKeyPairResult {
    return CASRSA::generate_rsa_keys(key_size).into();
}

#[napi]
pub fn encrypt_plaintext_rsa(public_key: String, plaintext: Vec<u8>) -> Vec<u8> {
    return CASRSA::encrypt_plaintext(public_key, plaintext);
}

#[napi]
pub fn decrypt_ciphertext_rsa(private_key: String, ciphertext: Vec<u8>) -> Vec<u8> {
    return CASRSA::decrypt_ciphertext(private_key, ciphertext);
}

#[napi]
pub fn sign_rsa(private_key: String, hash: Vec<u8>) -> Vec<u8> {
    return CASRSA::sign(private_key, hash);
}

#[napi]
pub fn verify_rsa(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> bool {
    return CASRSA::verify(public_key, hash, signature);
}
