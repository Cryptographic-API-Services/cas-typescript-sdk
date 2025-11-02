use crate::hybrid::types::{HpkeEncryptResult, HpkeKeyResult};
use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use napi_derive::napi;

#[napi]
pub fn hpke_generate_keypair() -> HpkeKeyResult {
    let (secret_key, public_key, info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    HpkeKeyResult {
        public_key: public_key,
        secret_key: secret_key,
        info_str: info_str
    }
}

#[napi]
pub fn generate_info_str() -> Vec<u8> {
    return <CASHPKE as CASHybrid>::generate_info_str();
}

#[napi]
pub fn hpke_encrypt(
    plaintext: Vec<u8>,
    public_key: Vec<u8>,
    info_str: Vec<u8>,
) -> HpkeEncryptResult {
    let encrypt_result: (Vec<u8>, Vec<u8>, Vec<u8>) =
        <CASHPKE as CASHybrid>::encrypt(plaintext, public_key, info_str);
    return HpkeEncryptResult {
        tag: encrypt_result.2,
        ciphertext: encrypt_result.1,
        encapsulated_key: encrypt_result.0,
    }
}

#[napi]
pub fn hpke_decrypt(
    ciphertext: Vec<u8>,
    private_key: Vec<u8>,
    encapped_key: Vec<u8>,
    tag: Vec<u8>,
    info_str: Vec<u8>,
) -> Vec<u8> {
    return <CASHPKE as CASHybrid>::decrypt(ciphertext, private_key, encapped_key, tag, info_str);
}

#[test]
pub fn hpke_encrypt_decrypt_test() {
    let hpke_keypair = hpke_generate_keypair();
    let plaintext = "This is a secret message".as_bytes().to_vec();
    let encrypt_result = hpke_encrypt(
        plaintext.clone(),
        hpke_keypair.public_key,
        hpke_keypair.info_str.clone(),
    );
    let decrypted_plaintext = hpke_decrypt(
        encrypt_result.ciphertext,
        hpke_keypair.secret_key,
        encrypt_result.encapsulated_key,
        encrypt_result.tag,
        hpke_keypair.info_str,
    );
    assert_eq!(plaintext, decrypted_plaintext);
}
