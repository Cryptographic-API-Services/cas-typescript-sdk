use napi::bindgen_prelude::Object;
use napi_derive::napi;
use rand::rngs::OsRng;
use rsa::{pkcs1::{EncodeRsaPublicKey}, pkcs8::{EncodePrivateKey},RsaPublicKey, RsaPrivateKey};

use super::cas_asymmetric_encryption::{CASRSAEncryption, RSAKeyPairResult};
pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    fn generate_rsa_keys(key_size: u32) -> RSAKeyPairResult {
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, key_size as usize).expect("failed to generate a key");
        let public_key: RsaPublicKey = private_key.to_public_key();
        let result = RSAKeyPairResult {
            public_key: public_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF).unwrap().to_string(),
            private_key: private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()
        };
        result
    }

    fn encrypt_plaintext(public_key: String, plaintext: Vec<u8>) -> Vec<u8> {
        todo!()
    }

    fn decrypt_ciphertext(private_key: String, ciphertext: Vec<u8>) -> Vec<u8> {
        todo!()
    }
}


#[napi]
pub fn generate_rsa_keys(key_size: u32) -> RSAKeyPairResult {
    return CASRSA::generate_rsa_keys(key_size);
}