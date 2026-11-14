use napi_derive::napi;

#[napi(object, js_name = "HpkeKeyResult")]
pub struct HpkeKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub info_str: Vec<u8>
}

#[napi(object, js_name = "HpkeEncryptResult")]
pub struct HpkeEncryptResult {
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
}