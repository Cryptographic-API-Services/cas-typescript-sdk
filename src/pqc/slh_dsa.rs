use cas_lib::pqc::cas_pqc::SlhDsaKeyPair;
use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use napi_derive::napi;

#[napi(constructor)]
pub struct CASSlhDsaKeyPairResult {
    pub signing_key: Vec<u8>,
    pub verification_key: Vec<u8>,
}

impl From<SlhDsaKeyPair> for CASSlhDsaKeyPairResult {
    fn from(result: SlhDsaKeyPair) -> Self {
        CASSlhDsaKeyPairResult {
            signing_key: result.signing_key,
            verification_key: result.verification_key,
        }
    }
}

#[napi]
pub fn slh_dsa_generate_key_pair() -> CASSlhDsaKeyPairResult {
    return generate_signing_and_verification_key().into();
}

#[napi]
pub fn slh_dsa_sign(message: Vec<u8>, signing_key: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(sign_message(message, signing_key))
}

#[napi]
pub fn slh_dsa_verify(message: Vec<u8>, signature: Vec<u8>, verification_key: Vec<u8>) -> napi::Result<bool> {
    crate::map_cas_err(verify_signature(message, signature, verification_key))
}

#[test]
fn slh_dsa_sign_verify_test() {
    let key_pair = slh_dsa_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    let signature = slh_dsa_sign(message.clone(), key_pair.signing_key).unwrap();
    let verified = slh_dsa_verify(message, signature, key_pair.verification_key).unwrap();
    assert_eq!(true, verified);
}

#[test]
fn slh_dsa_verify_tampered_message_fails_test() {
    let key_pair = slh_dsa_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    let signature = slh_dsa_sign(message, key_pair.signing_key).unwrap();
    let tampered_message = b"NotMyDataToSign2".to_vec();
    let verified = slh_dsa_verify(tampered_message, signature, key_pair.verification_key).unwrap();
    assert_eq!(false, verified);
}

#[test]
fn slh_dsa_rejects_bad_key_lengths_test() {
    let key_pair = slh_dsa_generate_key_pair();
    let message = b"NotMyDataToSign".to_vec();
    assert!(slh_dsa_sign(message.clone(), vec![0u8; 10]).is_err());
    let signature = slh_dsa_sign(message.clone(), key_pair.signing_key).unwrap();
    assert!(slh_dsa_verify(message, signature, vec![0u8; 10]).is_err());
}
