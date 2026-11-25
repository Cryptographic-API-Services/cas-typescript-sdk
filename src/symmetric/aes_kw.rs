use cas_lib::symmetric::{aes_kw::{CASAES128KW, CASAES256KW}, cas_symmetric_encryption::{CASAES128KeyWrap, CASAES256KeyWrap}};
use napi_derive::napi;

#[napi]
pub fn aes128_kw_generate_kek() -> Vec<u8> {
    <CASAES128KW as CASAES128KeyWrap>::generate_kek()
}

#[napi]
pub fn aes256_kw_generate_kek() -> Vec<u8> {
    <CASAES256KW as CASAES256KeyWrap>::generate_kek()
}

#[napi]
pub fn aes128_kw_wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128KW as CASAES128KeyWrap>::wrap_key(kek, key_to_wrap))
}

#[napi]
pub fn aes128_kw_unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128KW as CASAES128KeyWrap>::unwrap_key(kek, wrapped_key))
}

#[napi]
pub fn aes128_kw_wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128KW as CASAES128KeyWrap>::wrap_key_with_padding(kek, key_to_wrap))
}

#[napi]
pub fn aes128_kw_unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES128KW as CASAES128KeyWrap>::unwrap_key_with_padding(kek, wrapped_key))
}

#[napi]
pub fn aes256_kw_wrap_key(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256KW as CASAES256KeyWrap>::wrap_key(kek, key_to_wrap))
}

#[napi]
pub fn aes256_kw_unwrap_key(kek: Vec<u8>, wrapped_key: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256KW as CASAES256KeyWrap>::unwrap_key(kek, wrapped_key))
}

#[napi]
pub fn aes256_kw_wrap_key_with_padding(kek: Vec<u8>, key_to_wrap: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256KW as CASAES256KeyWrap>::wrap_key_with_padding(kek, key_to_wrap))
}

#[napi]
pub fn aes256_kw_unwrap_key_with_padding(kek: Vec<u8>, wrapped_key: Vec<u8>) -> crate::Result<Vec<u8>> {
    crate::map_cas_err(<CASAES256KW as CASAES256KeyWrap>::unwrap_key_with_padding(kek, wrapped_key))
}

#[test]
fn aes_kw_generate_kek_lengths_test() {
    assert_eq!(aes128_kw_generate_kek().len(), 16);
    assert_eq!(aes256_kw_generate_kek().len(), 32);
}

#[test]
fn aes128_kw_wrap_unwrap_test() {
    let kek = aes128_kw_generate_kek();
    let key = crate::symmetric::aes::aes128_key();
    let wrapped = aes128_kw_wrap_key(kek.clone(), key.clone()).unwrap();
    assert_eq!(wrapped.len(), key.len() + 8);
    assert_eq!(aes128_kw_unwrap_key(kek, wrapped).unwrap(), key);
}

#[test]
fn aes256_kw_wrap_unwrap_test() {
    let kek = aes256_kw_generate_kek();
    let key = crate::symmetric::aes::aes256_key();
    let wrapped = aes256_kw_wrap_key(kek.clone(), key.clone()).unwrap();
    assert_eq!(wrapped.len(), key.len() + 8);
    assert_eq!(aes256_kw_unwrap_key(kek, wrapped).unwrap(), key);
}

#[test]
fn aes_kwp_wrap_unwrap_any_length_test() {
    let kek128 = aes128_kw_generate_kek();
    let kek256 = aes256_kw_generate_kek();
    let key = crate::symmetric::aes::aes256_key();
    for len in [1, 7, 8, 9, 20, 32] {
        let data = key[..len].to_vec();
        let wrapped128 = aes128_kw_wrap_key_with_padding(kek128.clone(), data.clone()).unwrap();
        assert_eq!(wrapped128.len() % 8, 0);
        assert_eq!(aes128_kw_unwrap_key_with_padding(kek128.clone(), wrapped128).unwrap(), data);
        let wrapped256 = aes256_kw_wrap_key_with_padding(kek256.clone(), data.clone()).unwrap();
        assert_eq!(aes256_kw_unwrap_key_with_padding(kek256.clone(), wrapped256).unwrap(), data);
    }
}

#[test]
fn aes_kw_unwrap_tampered_fails_test() {
    let kek = aes256_kw_generate_kek();
    let key = crate::symmetric::aes::aes256_key();
    let mut wrapped = aes256_kw_wrap_key(kek.clone(), key.clone()).unwrap();
    wrapped[0] ^= 0xff;
    let err = aes256_kw_unwrap_key(kek.clone(), wrapped).unwrap_err();
    assert_eq!("CAS_DECRYPTION_FAILED", err.status.as_ref());

    let mut wrapped_padded = aes256_kw_wrap_key_with_padding(kek.clone(), key[..20].to_vec()).unwrap();
    let last = wrapped_padded.len() - 1;
    wrapped_padded[last] ^= 0x01;
    assert!(aes256_kw_unwrap_key_with_padding(kek, wrapped_padded).is_err());
}

#[test]
fn aes_kw_rejects_bad_input_test() {
    let kek128 = aes128_kw_generate_kek();
    let kek256 = aes256_kw_generate_kek();
    let key = crate::symmetric::aes::aes256_key();

    let err = aes128_kw_wrap_key(kek128.clone(), key[..20].to_vec()).unwrap_err();
    assert_eq!("CAS_INVALID_INPUT", err.status.as_ref());
    assert!(aes256_kw_wrap_key(kek256.clone(), key[..8].to_vec()).is_err());
    assert!(aes128_kw_wrap_key_with_padding(kek128.clone(), Vec::new()).is_err());

    let err = aes128_kw_wrap_key(kek256, key[..16].to_vec()).unwrap_err();
    assert_eq!("CAS_INVALID_KEY", err.status.as_ref());
    assert!(aes128_kw_unwrap_key(kek128, vec![0u8; 20]).is_err());
}
