use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};
use napi_derive::napi;

#[napi]
pub fn hmac_sign(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    return <HMAC as CASHMAC>::sign(key, message);
}

#[napi]
pub fn hmac_verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    return <HMAC as CASHMAC>::verify(key, message, signature);
}

#[test]
fn hmac_sign_and_verify_test() {
    let key = b"ThisIsMyKeyForHmac".to_vec();
    let message = b"ThisIsMyMessageToSign".to_vec();
    let signature = hmac_sign(key.clone(), message.clone());
    let result = hmac_verify(key, message, signature);
    assert_eq!(true, result);
}