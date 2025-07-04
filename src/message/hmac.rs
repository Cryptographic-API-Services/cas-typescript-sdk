use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};
use napi_derive::napi;

#[napi]
pub fn hmac_sign(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    return <HMAC as CASHMAC>::sign(key, message);
}

#[napi]
pub fn hmac_sign_threadpool(key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    return <HMAC as CASHMAC>::sign_threadpool(key, message);
}

#[napi]
pub fn hmac_verify(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    return <HMAC as CASHMAC>::verify(key, message, signature);
}

#[napi]
pub fn hmac_verify_threadpool(key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    return <HMAC as CASHMAC>::verify_threadpool(key, message, signature);
}

#[test]
fn hmac_sign_and_verify_test() {
    let key = b"ThisIsMyKeyForHmac".to_vec();
    let message = b"ThisIsMyMessageToSign".to_vec();
    let signature = hmac_sign(key.clone(), message.clone());
    let result = hmac_verify(key, message, signature);
    assert_eq!(true, result);
}

#[test]
fn hmac_sign_and_verify_threadpool_test() {
    let key = b"ThisIsMyKeyForHmac7789".to_vec();
    let message = b"ThisIsMyMessageToSign1230".to_vec();
    let signature = hmac_sign_threadpool(key.clone(), message.clone());
    let result = hmac_verify_threadpool(key, message, signature);
    assert_eq!(true, result);
}