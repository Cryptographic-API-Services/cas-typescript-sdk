use cas_lib::message::{cas_hmac::CASHMAC, hmac::{HMACSha512, HMAC}};
use napi_derive::napi;

#[napi]
pub fn hmac_sign(key: Vec<u8>, message: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<HMAC as CASHMAC>::sign(key, message))
}

#[napi]
pub fn hmac_verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> napi::Result<bool> {
    crate::map_cas_err(<HMAC as CASHMAC>::verify(key, message, signature))
}

#[napi]
pub fn hmac_sha512_sign(key: Vec<u8>, message: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(<HMACSha512 as CASHMAC>::sign(key, message))
}

#[napi]
pub fn hmac_sha512_verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> napi::Result<bool> {
    crate::map_cas_err(<HMACSha512 as CASHMAC>::verify(key, message, signature))
}

#[test]
fn hmac_sign_and_verify_test() {
    let key = b"ThisIsMyKeyForHmac".to_vec();
    let message = b"ThisIsMyMessageToSign".to_vec();
    let signature = hmac_sign(key.clone(), message.clone()).unwrap();
    let result = hmac_verify(key, message, signature).unwrap();
    assert_eq!(true, result);
}

#[test]
fn hmac_sha512_sign_and_verify_test() {
    let key = b"ThisIsMyKeyForHmac".to_vec();
    let message = b"ThisIsMyMessageToSign".to_vec();
    let signature = hmac_sha512_sign(key.clone(), message.clone()).unwrap();
    assert_eq!(64, signature.len());
    assert_eq!(true, hmac_sha512_verify(key.clone(), message, signature.clone()).unwrap());
    assert_eq!(false, hmac_sha512_verify(key, b"TamperedMessage".to_vec(), signature).unwrap());
}
