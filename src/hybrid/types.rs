use napi_derive::napi;

#[napi(constructor)]
pub struct HpkeKeyResult {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub info_str: Vec<u8>
}

#[napi(constructor)]
pub struct HpkeEncryptResult {
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub encapsulated_key: Vec<u8>,
}