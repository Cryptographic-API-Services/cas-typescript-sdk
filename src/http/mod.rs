use cas_lib::http::{set_base_url_in_cache, set_api_key_in_cache, send_benchmark, types::runtime::RUNTIME};
use napi_derive::napi;

#[napi]
pub fn set_base_url(base_url: String) {
    set_base_url_in_cache(base_url);
}

#[napi]
pub fn set_api_key(api_key: String) -> bool {
    RUNTIME.block_on(async {
        set_api_key_in_cache(api_key).await;
    });
    true
}

#[napi]
pub fn send_benchmark_to_api(time_in_milliseconds: i64, class_name: String, method_name: String) {
    RUNTIME.spawn(async move {
        send_benchmark(time_in_milliseconds, class_name, method_name).await;
    });
}