use std::sync::{Mutex, Once};

use fnv::FnvHashMap;
use once_cell::sync::Lazy;
use widestring::Utf16Str;

use crate::{core::{ext::Utf16StringExt, hachimi::AssetMetadata}, il2cpp::{
    api::il2cpp_resolve_icall, ext::{Il2CppObjectExt, Il2CppStringExt}, hook::{
        umamusume::{StoryRaceTextAsset, StoryTimelineData, TextDotData, TextRubyData},
        Cute_UI_Assembly::AtlasReference,
        UnityEngine_CoreModule::{GameObject, Texture2D}
    }, symbols::GCHandle, types::*
}};

pub const ASSET_PATH_PREFIX: &str = "assets/_gallopresources/bundle/resources/";

// 全局缓存mods bundles（只在第一次访问时加载一次，线程安全）
static mut MODS_BUNDLES_CACHE: Option<FnvHashMap<String, *mut Il2CppObject>> = None;
static INIT_MODS_BUNDLES: Once = Once::new();

fn get_mods_bundles_cache() -> &'static FnvHashMap<String, *mut Il2CppObject> {
    unsafe {
        INIT_MODS_BUNDLES.call_once(|| {
            use crate::{core::Hachimi, il2cpp::ext::LocalizedDataExt};
            let hachimi = Hachimi::instance();
            let localized_data = hachimi.localized_data.load();
            let mods_bundles = localized_data.load_mods_asset_bundles();

            println!("Loaded {} mod asset bundles into global cache", mods_bundles.len());
            for (name, _) in &mods_bundles {
                println!("Loaded mod asset bundle: '{}'", name);
            }

            MODS_BUNDLES_CACHE = Some(mods_bundles);
        });
        MODS_BUNDLES_CACHE.as_ref().unwrap()
    }
}

pub struct RequestInfo {
    pub name_handle: GCHandle,
    pub bundle: usize // *mut Il2CppObject (this)
}
impl RequestInfo {
    pub fn name(&self) -> *mut Il2CppString {
        self.name_handle.target() as _
    }
}
pub static REQUEST_INFOS: Lazy<Mutex<FnvHashMap<usize, RequestInfo>>> = Lazy::new(|| Mutex::default());

static BUNDLE_PATHS: Lazy<Mutex<FnvHashMap<usize, GCHandle>>> = Lazy::new(|| Mutex::default());
pub fn get_bundle_path(this: *mut Il2CppObject) -> Option<*mut Il2CppString> {
    Some(BUNDLE_PATHS.lock().unwrap().get(&(this as usize))?.target() as _)
}

pub fn check_asset_bundle_name(this: *mut Il2CppObject, metadata: &AssetMetadata) -> bool {
    if let Some(meta_bundle_name) = &metadata.bundle_name {
        if let Some(bundle_path) = get_bundle_path(this) {
            let bundle_name = unsafe { (*bundle_path).as_utf16str().path_filename() };
            if !bundle_name.str_eq(&meta_bundle_name) {
                warn!("Expected bundle {}, got {}", meta_bundle_name, bundle_name);
                return false;
            }
        }
    }

    true
}

type LoadAssetFn = extern "C" fn(this: *mut Il2CppObject, name: *mut Il2CppString, type_: *mut Il2CppObject) -> *mut Il2CppObject;
extern "C" fn LoadAsset_Internal(this: *mut Il2CppObject, name: *mut Il2CppString, type_: *mut Il2CppObject) -> *mut Il2CppObject {
    // 只用全局缓存的mods bundles，不再每次重新加载
    let mods_bundles = get_mods_bundles_cache();
    for (_bundle_name, mod_bundle) in mods_bundles.iter() {
        if mod_bundle.is_null() {
            continue;
        }

        // 尝试从mod bundle加载同名资源
        let mod_asset = get_orig_fn!(LoadAsset_Internal, LoadAssetFn)(*mod_bundle, name, type_);
        if !mod_asset.is_null() {
            // 找到mod资源，使用mod版本
            on_LoadAsset(*mod_bundle, mod_asset, name);
            return mod_asset;
        }
    }

    // mod中没有找到，使用原始资源
    let asset = get_orig_fn!(LoadAsset_Internal, LoadAssetFn)(this, name, type_);
    on_LoadAsset(this, asset, name);
    asset
}

pub fn LoadAsset_Internal_orig(this: *mut Il2CppObject, name: *mut Il2CppString, type_: *mut Il2CppObject) -> *mut Il2CppObject {
    get_orig_fn!(LoadAsset_Internal, LoadAssetFn)(this, name, type_)
}

type LoadAssetAsyncFn = extern "C" fn(this: *mut Il2CppObject, name: *mut Il2CppString, type_: *mut Il2CppObject) -> *mut Il2CppObject;
extern "C" fn LoadAssetAsync_Internal(this: *mut Il2CppObject, name: *mut Il2CppString, type_: *mut Il2CppObject) -> *mut Il2CppObject {
    let request = get_orig_fn!(LoadAssetAsync_Internal, LoadAssetAsyncFn)(this, name, type_);
    let info = RequestInfo {
        name_handle: GCHandle::new(name as _, false), // is name even guaranteed to survive in memory..?
        bundle: this as usize
    };
    REQUEST_INFOS.lock().unwrap().insert(request as usize, info);
    request
}

type OnLoadAssetFn = fn(bundle: *mut Il2CppObject, asset: *mut Il2CppObject, name: &Utf16Str);
pub fn on_LoadAsset(bundle: *mut Il2CppObject, asset: *mut Il2CppObject, name: *mut Il2CppString) {
    let class = unsafe { (*asset).klass() };
    //debug!("{} {}", unsafe { std::ffi::CStr::from_ptr((*class).name).to_str().unwrap() }, unsafe { (*name).as_utf16str() });

    let handler: OnLoadAssetFn = if class == GameObject::class() {
        GameObject::on_LoadAsset
    }
    else if class == StoryTimelineData::class() {
        StoryTimelineData::on_LoadAsset
    }
    else if class == Texture2D::class() {
        Texture2D::on_LoadAsset
    }
    else if class == AtlasReference::class() {
        AtlasReference::on_LoadAsset
    }
    else if class == StoryRaceTextAsset::class() {
        StoryRaceTextAsset::on_LoadAsset
    }
    else if class == TextRubyData::class() {
        TextRubyData::on_LoadAsset
    }
    else if class == TextDotData::class() {
        TextDotData::on_LoadAsset
    }
    else {
        return;
    };

    handler(bundle, asset, unsafe { (*name).as_utf16str() });
}

type LoadFromFileInternalFn = extern "C" fn(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject;
extern "C" fn LoadFromFile_Internal(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject {
    let bundle = get_orig_fn!(LoadFromFile_Internal, LoadFromFileInternalFn)(path, crc, offset);
    if !bundle.is_null() {
        BUNDLE_PATHS.lock().unwrap().insert(bundle as usize, GCHandle::new(path as _, false));
    }
    bundle
}

pub fn LoadFromFile_Internal_orig(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject {
    get_orig_fn!(LoadFromFile_Internal, LoadFromFileInternalFn)(path, crc, offset)
}

type UnloadFn = extern "C" fn(this: *mut Il2CppObject, unload_all_loaded_objects: bool);
extern "C" fn Unload(this: *mut Il2CppObject, unload_all_loaded_objects: bool) {
    BUNDLE_PATHS.lock().unwrap().remove(&(this as usize));
    get_orig_fn!(Unload, UnloadFn)(this, unload_all_loaded_objects);
}

pub fn init(_UnityEngine_AssetBundleModule: *const Il2CppImage) {
    //get_class_or_return!(UnityEngine_AssetBundleModule, UnityEngine, AssetBundle);

    let LoadAsset_Internal_addr = il2cpp_resolve_icall(
        c"UnityEngine.AssetBundle::LoadAsset_Internal(System.String,System.Type)".as_ptr()
    );
    let LoadAssetAsync_Internal_addr = il2cpp_resolve_icall(
        c"UnityEngine.AssetBundle::LoadAssetAsync_Internal(System.String,System.Type)".as_ptr()
    );
    let LoadFromFile_Internal_addr = il2cpp_resolve_icall(
        c"UnityEngine.AssetBundle::LoadFromFile_Internal(System.String,System.UInt32,System.UInt64)".as_ptr()
    );
    let Unload_addr = il2cpp_resolve_icall(
        c"UnityEngine.AssetBundle::Unload(System.Boolean)".as_ptr()
    );

    new_hook!(LoadAsset_Internal_addr, LoadAsset_Internal);
    new_hook!(LoadAssetAsync_Internal_addr, LoadAssetAsync_Internal);
    new_hook!(LoadFromFile_Internal_addr, LoadFromFile_Internal);
    new_hook!(Unload_addr, Unload);
}