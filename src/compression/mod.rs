use napi_derive::napi;
use cas_lib::compression::zstd;

#[napi]
pub fn ztsd_compress(data: Vec<u8>, level: i32) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(zstd::compress(data, level))
}

#[napi]
pub fn ztsd_decompress(data: Vec<u8>) -> napi::Result<Vec<u8>> {
    crate::map_cas_err(zstd::decompress(data))
}