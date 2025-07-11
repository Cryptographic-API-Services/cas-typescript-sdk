use cas_lib::digital_signature::{cas_digital_signature_rsa::{ED25519DigitalSignature, SHAED25519DalekDigitalSignatureResult}, sha_512_ed25519::SHA512ED25519DigitalSignature};

use napi_derive::napi;

use super::types::CASSHAED25519DalekDigitalSignatureResult;


#[napi]
pub fn sha_512_ed25519_digital_signature(data_to_sign: Vec<u8>) -> CASSHAED25519DalekDigitalSignatureResult {
    return <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(data_to_sign).into();
}

#[napi]
pub fn sha_512_ed25519_digital_signature_verify(public_key: Vec<u8>, data_to_verify: Vec<u8>, signature: Vec<u8>) -> bool {
    return <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(
        public_key,
        data_to_verify,
        signature,
    );
}

#[test]
fn sha_512_ed25519_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: SHAED25519DalekDigitalSignatureResult = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(data_to_sign.clone());
    let is_verified: bool = SHA512ED25519DigitalSignature::digital_signature_ed25519_verify(signature_result.public_key, data_to_sign, signature_result.signature);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_ed25519_test_fail() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: CASSHAED25519DalekDigitalSignatureResult = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(data_to_sign.clone()).into();
    let not_original_data = b"NOtTHoseBytes".to_vec();
    let is_verified: bool = SHA512ED25519DigitalSignature::digital_signature_ed25519_verify(
        signature_result.public_key,
        not_original_data,
        signature_result.signature,
    );
    assert_eq!(is_verified, false);
}