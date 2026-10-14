use cas_lib::pqc::cas_pqc::MlDsaKeyPair;
use cas_lib::pqc::ml_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASMlDsaKeyPairResult {
    pub signing_key: Vec<u8>,
    pub verification_key: Vec<u8>,
}

impl From<MlDsaKeyPair> for CASMlDsaKeyPairResult {
    fn from(result: MlDsaKeyPair) -> Self {
        CASMlDsaKeyPairResult {
            signing_key: result.signing_key,
            verification_key: result.verification_key,
        }
    }
}

#[napi]
pub fn ml_dsa65_generate_key_pair() -> CASMlDsaKeyPairResult {
    return generate_signing_and_verification_key().into();
}

#[napi]
pub fn ml_dsa65_sign(message: Vec<u8>, signing_key: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(sign_message(message, signing_key))
}

#[napi]
pub fn ml_dsa65_verify(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> napi::Result<bool> {
    crate::map_cas_err(verify_signature(message, signature, verification_key))
}

#[test]
fn ml_dsa65_sign_verify_test() {
    let key_pair = ml_dsa65_generate_key_pair();
    assert_eq!(32, key_pair.signing_key.len());
    assert_eq!(1952, key_pair.verification_key.len());
    let message = b"NotMyDataToSign".to_vec();
    let signature = ml_dsa65_sign(message.clone(), key_pair.signing_key).unwrap();
    assert_eq!(3309, signature.len());
    let verified = ml_dsa65_verify(message, signature, key_pair.verification_key).unwrap();
    assert_eq!(true, verified);
}

#[test]
fn ml_dsa65_sign_is_deterministic_test() {
    let key_pair = ml_dsa65_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    let first = ml_dsa65_sign(message.clone(), key_pair.signing_key.clone()).unwrap();
    let second = ml_dsa65_sign(message, key_pair.signing_key).unwrap();
    assert_eq!(first, second);
}

#[test]
fn ml_dsa65_verify_tampered_message_fails_test() {
    let key_pair = ml_dsa65_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    let signature = ml_dsa65_sign(message, key_pair.signing_key).unwrap();
    let tampered_message = b"NotMyDataToSign2".to_vec();
    let verified = ml_dsa65_verify(tampered_message, signature, key_pair.verification_key).unwrap();
    assert_eq!(false, verified);
}

#[test]
fn ml_dsa65_rejects_bad_lengths_test() {
    let key_pair = ml_dsa65_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    assert!(ml_dsa65_sign(message.clone(), vec![0u8; 10]).is_err());
    let signature = ml_dsa65_sign(message.clone(), key_pair.signing_key).unwrap();
    assert!(ml_dsa65_verify(message.clone(), signature, vec![0u8; 10]).is_err());
    assert!(ml_dsa65_verify(message, vec![0u8; 10], key_pair.verification_key).is_err());
}
