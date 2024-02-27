use napi_derive::napi;

#[napi(constructor)]
pub struct AesKeyFromX25519SharedSecret {
    pub aes_key: Vec<u8>,
    pub aes_nonce: Vec<u8>,
}

pub trait CASAESEncryption {
    fn generate_key() -> Vec<u8>;
    fn encrypt_plaintext(aes_key: Vec<u8>, nonce: Vec<u8>, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt_ciphertext(aes_key: Vec<u8>, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8>;
    fn key_from_x25519_shared_secret(shared_secret: Vec<u8>) -> AesKeyFromX25519SharedSecret;
}
