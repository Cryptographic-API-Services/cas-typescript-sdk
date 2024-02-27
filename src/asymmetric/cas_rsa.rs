use napi_derive::napi;
use rand::rngs::OsRng;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
};

use super::cas_asymmetric_encryption::{CASRSAEncryption, RSAKeyPairResult};
pub struct CASRSA;

impl CASRSAEncryption for CASRSA {
    fn generate_rsa_keys(key_size: u32) -> RSAKeyPairResult {
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey =
            RsaPrivateKey::new(&mut rng, key_size as usize).expect("failed to generate a key");
        let public_key: RsaPublicKey = private_key.to_public_key();
        let result = RSAKeyPairResult {
            public_key: public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
            private_key: private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        };
        result
    }

    fn encrypt_plaintext(public_key: String, plaintext: Vec<u8>) -> Vec<u8> {
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let mut rng = rand::thread_rng();
        let ciphertext = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, &plaintext)
            .unwrap();
        ciphertext
    }

    fn decrypt_ciphertext(private_key: String, ciphertext: Vec<u8>) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
        let plaintext = private_key.decrypt(Pkcs1v15Encrypt, &ciphertext).unwrap();
        plaintext
    }

    fn sign(private_key: String, hash: Vec<u8>) -> Vec<u8> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key).unwrap();
        let mut signed_data = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &hash)
            .unwrap();
        signed_data
    }

    fn verify(public_key: String, hash: Vec<u8>, signature: Vec<u8>) -> bool {
        let public_key = RsaPublicKey::from_pkcs1_pem(&public_key).unwrap();
        let verified = public_key.verify(Pkcs1v15Sign::new_unprefixed(), &hash, &signature);
        if verified.is_err() == false {
            return true;
        } else {
            return false;
        }
    }
}

#[napi]
pub fn generate_rsa_keys(key_size: u32) -> RSAKeyPairResult {
    return CASRSA::generate_rsa_keys(key_size);
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
