use std::time::Duration;

use crate::core::Hachimi;
use crate::il2cpp::symbols::{get_method_addr, Array};
use crate::il2cpp::types::Il2CppArray;
use crate::il2cpp::types::Il2CppImage;
use once_cell::sync::Lazy;
use ureq;

static TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    Duration::from_millis(Hachimi::instance().config.load().notifier_timeout_ms)
});
// https://github.com/algesten/ureq/issues/707
static AGENT: Lazy<ureq::Agent> = Lazy::new(|| {
    ureq::AgentBuilder::new()
        .timeout_connect(*TIMEOUT)
        .timeout_read(*TIMEOUT)
        .timeout_write(*TIMEOUT)
        .build()
});
static REQUEST: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/request");
static RESPONSE: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/response");

type CompressRequestFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;
type DecompressResponseFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;

extern "C" fn CompressRequest(data: *mut Il2CppArray) -> *mut Il2CppArray {
    unsafe {
        let buffer = Array::<u8>::from(data);
        let _ = AGENT.post(&REQUEST).send_bytes(&buffer.as_slice());
    }
    get_orig_fn!(CompressRequest, CompressRequestFn)(data)
}
extern "C" fn DecompressResponse(data: *mut Il2CppArray) -> *mut Il2CppArray {
    let decompressed = get_orig_fn!(DecompressResponse, DecompressResponseFn)(data);
    unsafe {
        let buffer = Array::<u8>::from(decompressed);
        let _ = AGENT.post(&RESPONSE).send_bytes(&buffer.as_slice());
    }
    decompressed
}

pub fn init(img: *const Il2CppImage) {
    get_class_or_return!(img, "Gallop", HttpHelper);

    let COMPRESSREQUEST_ADDR = get_method_addr(HttpHelper, c"CompressRequest", 1);
    let DECOMPRESSRESPONSE_ADDR = get_method_addr(HttpHelper, c"DecompressResponse", 1);

    new_hook!(COMPRESSREQUEST_ADDR, CompressRequest);
    new_hook!(DECOMPRESSRESPONSE_ADDR, DecompressResponse);
}
