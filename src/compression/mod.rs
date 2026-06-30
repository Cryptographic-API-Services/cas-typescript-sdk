use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use cas_lib::compression::zstd;

#[napi]
pub fn ztsd_compress(data: Uint8Array, level: i32) -> napi::Result<Uint8Array> {
    crate::map_cas_err(zstd::compress(data.to_vec(), level)).map(Uint8Array::from)
}

#[napi]
pub fn ztsd_decompress(data: Uint8Array) -> napi::Result<Uint8Array> {
    crate::map_cas_err(zstd::decompress(data.to_vec())).map(Uint8Array::from)
}
