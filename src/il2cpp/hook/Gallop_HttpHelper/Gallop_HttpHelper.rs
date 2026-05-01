use std::{fs, sync::RwLock, time::Duration};

use chrono::Local;
use crate::core::Hachimi;
use crate::il2cpp::ext::Il2CppStringExt;
use crate::il2cpp::symbols::{get_assembly_image, get_class, get_method_addr, Array};
use crate::il2cpp::types::{Il2CppArray, Il2CppImage, Il2CppObject, Il2CppString};
use once_cell::sync::Lazy;
use ureq;

static TIMEOUT: Lazy<Duration> = Lazy::new(|| {
    Duration::from_millis(Hachimi::instance().config.load().notifier_timeout_ms)
});
// https://github.com/algesten/ureq/issues/707
static AGENT: Lazy<ureq::Agent> = Lazy::new(|| {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(*TIMEOUT))
        .timeout_recv_response(Some(*TIMEOUT))
        .timeout_send_body(Some(*TIMEOUT))
        .build();
    config.into()
});
static REQUEST: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/request");
static RESPONSE: Lazy<String> = Lazy::new(|| Hachimi::instance().config.load().notifier_host.clone() + "/notify/response");
static LAST_POST_URL: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
const RACE_URL_KEYWORDS: [&str; 3] = ["race_start", "race_replay", "get_saved_race_result"];

type CompressRequestFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;
type DecompressResponseFn = extern "C" fn(data: *mut Il2CppArray) -> *mut Il2CppArray;
type PostFn = extern "C" fn(
    this: *mut Il2CppObject,
    url: *mut Il2CppString,
    post_data: *mut Il2CppObject,
    headers: *mut Il2CppObject,
) -> *mut Il2CppObject;

extern "C" fn Post(
    this: *mut Il2CppObject,
    url: *mut Il2CppString,
    post_data: *mut Il2CppObject,
    headers: *mut Il2CppObject,
) -> *mut Il2CppObject {
    if let Some(url_ref) = unsafe { url.as_ref() } {
        let url_str = url_ref.as_utf16str().to_string();
        if let Ok(mut guard) = LAST_POST_URL.write() {
            *guard = url_str;
        }
    }

    get_orig_fn!(Post, PostFn)(this, url, post_data, headers)
}

fn save_response_msgpack(data: &[u8]) {
    if !Hachimi::instance().config.load().enable_race_response_dump {
        return;
    }

    if !is_target_race_response_url() {
        return;
    }

    let hachimi = Hachimi::instance();
    let out_dir = hachimi.get_data_path("race");
    if let Err(e) = fs::create_dir_all(&out_dir) {
        warn!("Failed to create response dump dir {}: {}", out_dir.display(), e);
        return;
    }

    let now = Local::now();
    let url_suffix = current_url_suffix();
    let out_path = out_dir.join(format!(
        "{} {}.msgpack",
        now.format("%Y-%m-%d %H-%M-%S-%3f"),
        sanitize_filename_component(&url_suffix)
    ));

    if let Err(e) = fs::write(&out_path, data) {
        warn!("Failed to write response dump {}: {}", out_path.display(), e);
    }
}

fn is_target_race_response_url() -> bool {
    LAST_POST_URL
        .read()
        .map(|url| RACE_URL_KEYWORDS.iter().any(|keyword| url.contains(keyword)))
        .unwrap_or(false)
}

fn current_url_suffix() -> String {
    LAST_POST_URL
        .read()
        .ok()
        .and_then(|url| {
            let trimmed = url.trim_end_matches('/');
            if trimmed.is_empty() {
                None
            } else {
                trimmed.rsplit('/').next().map(|s| s.to_string())
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn sanitize_filename_component(input: &str) -> String {
    const ILLEGAL: &str = "\\/:*?\"<>|";
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control() || ILLEGAL.contains(c) {
            out.push('-');
        } else {
            out.push(c);
        }
    }

    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

extern "C" fn CompressRequest(data: *mut Il2CppArray) -> *mut Il2CppArray {
    unsafe {
        let buffer = Array::<u8>::from(data);
        let _ = AGENT.post(REQUEST.as_str()).send(&*buffer.as_slice());
    }
    get_orig_fn!(CompressRequest, CompressRequestFn)(data)
}
extern "C" fn DecompressResponse(data: *mut Il2CppArray) -> *mut Il2CppArray {
    let decompressed = get_orig_fn!(DecompressResponse, DecompressResponseFn)(data);
    unsafe {
        let buffer = Array::<u8>::from(decompressed);
        let data = buffer.as_slice();
        save_response_msgpack(data);
        let _ = AGENT.post(RESPONSE.as_str()).send(&*data);
    }
    decompressed
}

pub fn init(img: *const Il2CppImage) {
    get_class_or_return!(img, "Gallop", HttpHelper);

    if let Ok(cute_http_img) = get_assembly_image(c"Cute.Http.Assembly.dll") {
        if let Ok(www_request) = get_class(cute_http_img, c"Cute.Http", c"WWWRequest") {
            let POST_ADDR = get_method_addr(www_request, c"Post", 3);
            new_hook!(POST_ADDR, Post);
        }
    }

    let COMPRESSREQUEST_ADDR = get_method_addr(HttpHelper, c"CompressRequest", 1);
    let DECOMPRESSRESPONSE_ADDR = get_method_addr(HttpHelper, c"DecompressResponse", 1);

    new_hook!(COMPRESSREQUEST_ADDR, CompressRequest);
    new_hook!(DECOMPRESSRESPONSE_ADDR, DecompressResponse);
}
