use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi]
pub fn hmac_sign(key: Uint8Array, message: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(<HMAC as CASHMAC>::sign(key.to_vec(), message.to_vec())).map(Uint8Array::from)
}

#[napi]
pub fn hmac_verify(key: Uint8Array, message: Uint8Array, signature: Uint8Array) -> napi::Result<bool> {
    crate::map_cas_err(<HMAC as CASHMAC>::verify(key.to_vec(), message.to_vec(), signature.to_vec()))
}

#[test]
fn hmac_sign_and_verify_test() {
    let key = b"ThisIsMyKeyForHmac".to_vec();
    let message = b"ThisIsMyMessageToSign".to_vec();
    let signature = hmac_sign(key.clone().into(), message.clone().into()).unwrap();
    let result = hmac_verify(key.into(), message.into(), signature).unwrap();
    assert_eq!(true, result);
}
