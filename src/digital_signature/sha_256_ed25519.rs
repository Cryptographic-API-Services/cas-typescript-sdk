use cas_lib::digital_signature::{cas_digital_signature_rsa::ED25519DigitalSignature, sha_256_ed25519::SHA256ED25519DigitalSignature};
use napi_derive::napi;

use super::types::CASSHAED25519DalekDigitalSignatureResult;

#[napi]
pub fn sha_256_ed25519_digital_signature(data_to_sign: Vec<u8>) -> CASSHAED25519DalekDigitalSignatureResult {
    return <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(&data_to_sign).into();
}

#[napi]
pub fn sha_256_ed25519_digital_signature_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
    if public_key.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut pk: [u8; 32] = public_key.try_into().expect("public_key must be 32 bytes");
    let mut sig = signature.try_into().expect("signature must be 64 bytes");
    SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, &data_to_verify, sig)
}


#[test]
fn sha_256_ed25519_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(&data_to_sign.clone()).into();
    let mut pk: [u8; 32] = signature_result.public_key.try_into().expect("public_key must be 32 bytes");
    let mut sig: [u8; 64] = signature_result.signature.try_into().expect("signature must be 64 bytes");
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, data_to_sign, sig);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_ed25519_test_fail() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(&data_to_sign.clone()).into();
    let not_original_data = b"NOtTHoseBytes";
    let mut pk: [u8; 32] = signature_result.public_key.try_into().expect("public_key must be 32 bytes");
    let mut sig: [u8; 64] = signature_result.signature.try_into().expect("signature must be 64 bytes");
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, not_original_data, sig);
    assert_eq!(is_verified, false);
}