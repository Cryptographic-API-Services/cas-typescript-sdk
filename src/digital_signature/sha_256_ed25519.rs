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
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public_key[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature[..64]);
    SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, &data_to_verify, sig)
}


#[test]
fn sha_256_ed25519_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(&data_to_sign.clone()).into();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&signature_result.public_key[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature_result.signature[..64]);
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, data_to_sign, sig);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_ed25519_test_fail() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = SHA256ED25519DigitalSignature::digital_signature_ed25519(&data_to_sign.clone()).into();
    let not_original_data = b"NOtTHoseBytes";
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&signature_result.public_key[..32]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature_result.signature[..64]);
    let is_verified: bool = SHA256ED25519DigitalSignature::digital_signature_ed25519_verify(pk, not_original_data, sig);
    assert_eq!(is_verified, false);
}