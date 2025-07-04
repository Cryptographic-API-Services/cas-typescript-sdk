use cas_lib::digital_signature::{cas_digital_signature_rsa::{ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult}, sha_512_ed25519::SHA512ED25519DigitalSignature};

use napi_derive::napi;

use super::types::CASSHAED25519DalekDigitalSignatureResult;


#[napi]
pub fn sha_512_ed25519_digital_signature(data_to_sign: Vec<u8>) -> CASSHAED25519DalekDigitalSignatureResult {
    return <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(&data_to_sign).into();
}

#[napi]
pub fn sha_512_ed25519_digital_signature_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
    let public_key_array: [u8; 32] = public_key.try_into().expect("public_key must be 32 bytes");
    let signature_array: [u8; 64] = signature.try_into().expect("signature must be 64 bytes");
    return <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(
        public_key_array,
        &data_to_verify,
        signature_array,
    );
}

#[test]
fn sha_512_ed25519_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: SHAED25519DalekDigitalSignatureResult = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(&data_to_sign.clone());
    let is_verified: bool = SHA512ED25519DigitalSignature::digital_signature_ed25519_verify(signature_result.public_key, data_to_sign, signature_result.signature);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_ed25519_test_fail() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes";
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(&data_to_sign.clone()).into();
    let not_original_data = b"NOtTHoseBytes".to_vec();
    let public_key_array: [u8; 32] = signature_result.public_key.clone().try_into().expect("public_key must be 32 bytes");
    let signature_array: [u8; 64] = signature_result.signature.clone().try_into().expect("signature must be 64 bytes");
    let is_verified: bool = SHA512ED25519DigitalSignature::digital_signature_ed25519_verify(
        public_key_array,
        &not_original_data,
        signature_array,
    );
    assert_eq!(is_verified, false);
}