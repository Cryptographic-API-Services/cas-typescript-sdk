use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

#[napi(constructor)]
pub struct HpkeKeyResult {
    pub public_key: Uint8Array,
    pub secret_key: Uint8Array,
    pub info_str: Uint8Array
}

#[napi(constructor)]
pub struct HpkeEncryptResult {
    pub tag: Uint8Array,
    pub ciphertext: Uint8Array,
    pub encapsulated_key: Uint8Array,
}
