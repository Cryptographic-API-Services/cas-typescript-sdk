use cas_lib::digital_signature::{cas_digital_signature_rsa::RSADigitalSignature, sha_512_rsa::SHA512RSADigitalSignature};
use napi_derive::napi;

use super::types::CASRSADigitalSignatureResult;

#[napi]
pub fn sha_512_rsa_digital_signature(
    rsa_key_size: u32,
    data_to_sign: Vec<u8>,
) -> CASRSADigitalSignatureResult {
    return <SHA512RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa(rsa_key_size, data_to_sign).into();
}

#[napi]
pub fn sha_512_rsa_verify_digital_signature(
    public_key: String,
    data_to_verify: Vec<u8>,
    signature: Vec<u8>,
) -> bool {
    return <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa(public_key, data_to_verify, signature);
}

#[test]
fn sha_512_rsa_digital_signature_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: CASRSADigitalSignatureResult = SHA512RSADigitalSignature::digital_signature_rsa(key_size, data_to_sign.clone()).into();
    let is_verified: bool = <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa(signature_result.public_key, data_to_sign, signature_result.signature);
    assert_eq!(is_verified, true);
}

#[test]
fn sha_512_rsa_digital_signature_fail_test() {
    let key_size: u32 = 1024;
    let data_to_sign = b"GetTheseBytes".to_vec();
    let signature_result: CASRSADigitalSignatureResult = SHA512RSADigitalSignature::digital_signature_rsa(key_size, data_to_sign.clone()).into();
    let new_data = b"NOtTheOriginalData".to_vec();
    let is_verified: bool = <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa(signature_result.public_key, new_data, signature_result.signature);
    assert_eq!(is_verified, false);
}
