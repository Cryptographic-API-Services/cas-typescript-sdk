use cas_lib::asymmetric::{cas_rsa::CASRSA, types::{CASRSAEncryption, RSAKeyPairResult}};
use napi_derive::napi;

#[napi(object, js_name = "CASRSAKeyPairResult")]
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
pub fn generate_rsa_keys(key_size: u32) -> crate::Result<CASRSAKeyPairResult> {
    Ok(crate::map_cas_err(CASRSA::generate_rsa_keys(key_size as usize))?.into())
}

#[napi]
pub fn sign_rsa(private_key: String, message: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASRSA::sign(private_key, message))
}

#[napi]
pub fn verify_rsa(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> crate::Result<bool> {
    crate::map_cas_err(CASRSA::verify(public_key, message, signature))
}

#[napi]
pub fn sign_rsa_pss(private_key: String, message: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(CASRSA::sign_pss(private_key, message))
}

#[napi]
pub fn verify_rsa_pss(public_key: String, message: Vec<u8>, signature: Vec<u8>) -> crate::Result<bool> {
    crate::map_cas_err(CASRSA::verify_pss(public_key, message, signature))
}

#[test]
fn rsa_sign_verify_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let message = "NotMyDataToSign".as_bytes().to_vec();
    let signature = sign_rsa(key_pair.private_key, message.clone()).unwrap();
    let verified = verify_rsa(key_pair.public_key, message, signature).unwrap();
    assert_eq!(true, verified);
}

#[test]
fn rsa_sign_long_message_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let message = vec![0xabu8; 4096];
    let signature = sign_rsa(key_pair.private_key, message.clone()).unwrap();
    assert_eq!(signature.len(), 256);
    assert_eq!(true, verify_rsa(key_pair.public_key, message, signature).unwrap());
}

#[test]
fn rsa_key_sizes_test() {
    assert!(generate_rsa_keys(1024).is_err());
    let key_pair = generate_rsa_keys(3072).unwrap();
    let message = "NotMyDataToSign".as_bytes().to_vec();
    let signature = sign_rsa(key_pair.private_key, message.clone()).unwrap();
    assert_eq!(true, verify_rsa(key_pair.public_key, message, signature).unwrap());
}

#[test]
fn rsa_verify_fail_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let message = "NotMyDataToSign".as_bytes().to_vec();
    let signature = sign_rsa(key_pair.private_key, message).unwrap();
    let tampered_message = "NotMyDataToSign2".as_bytes().to_vec();
    let verified = verify_rsa(key_pair.public_key, tampered_message, signature).unwrap();
    assert_eq!(false, verified);
}

#[test]
fn rsa_pss_sign_verify_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let message = "NotMyDataToSign".as_bytes().to_vec();
    let signature = sign_rsa_pss(key_pair.private_key.clone(), message.clone()).unwrap();
    assert_eq!(signature.len(), 256);
    assert_eq!(true, verify_rsa_pss(key_pair.public_key.clone(), message.clone(), signature.clone()).unwrap());
    let second_signature = sign_rsa_pss(key_pair.private_key, message.clone()).unwrap();
    assert_ne!(signature, second_signature);
    assert_eq!(true, verify_rsa_pss(key_pair.public_key, message, second_signature).unwrap());
}

#[test]
fn rsa_pss_verify_fail_test() {
    let key_pair = generate_rsa_keys(2048).unwrap();
    let other_key_pair = generate_rsa_keys(2048).unwrap();
    let message = "NotMyDataToSign".as_bytes().to_vec();
    let signature = sign_rsa_pss(key_pair.private_key.clone(), message.clone()).unwrap();
    let tampered_message = "NotMyDataToSign2".as_bytes().to_vec();
    assert_eq!(false, verify_rsa_pss(key_pair.public_key.clone(), tampered_message, signature.clone()).unwrap());
    assert_eq!(false, verify_rsa_pss(other_key_pair.public_key, message.clone(), signature.clone()).unwrap());
    assert_eq!(false, verify_rsa(key_pair.public_key.clone(), message.clone(), signature).unwrap());
    let pkcs1v15_signature = sign_rsa(key_pair.private_key, message.clone()).unwrap();
    assert_eq!(false, verify_rsa_pss(key_pair.public_key, message, pkcs1v15_signature).unwrap());
}
