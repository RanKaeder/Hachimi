use std::sync::{Mutex, Once};

use fnv::FnvHashMap;
use once_cell::sync::Lazy;
use widestring::Utf16Str;

use crate::{core::{Hachimi, ext::Utf16StringExt, game::Region, hachimi::AssetMetadata}, il2cpp::{
    api::il2cpp_resolve_icall, ext::{Il2CppObjectExt, Il2CppStringExt}, hook::{
        umamusume::{StoryParamChangeEffect, StoryRaceTextAsset, StoryTimelineData, TextDotData, TextRubyData},
        Cute_UI_Assembly::AtlasReference,
        UnityEngine_CoreModule::{GameObject, Texture2D, Object}
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

pub fn check_asset_bundle_name(this: *mut Il2CppObject, metadata: &AssetMetadata) -> bool {
    if let Some(meta_bundle_name) = &metadata.bundle_name {
        let name_ptr = Object::get_name(this);
        if Hachimi::instance().game.region == Region::Japan {
            if !name_ptr.is_null() {
                let logical_name = unsafe { (*name_ptr).as_utf16str().path_filename() };

                if let Some(real_hash) = crate::il2cpp::sql::MetaData::get_hash(&logical_name.to_string()) {
                    if real_hash == *meta_bundle_name {
                        return true;
                    } else {
                        warn!("Expected bundle {}, got {}", meta_bundle_name, real_hash);
                        return false;
                    }
                }
    
                return false;
            }
        } else {
            return true; // Unsolved for other regions for now
        }

        warn!("Failed to resolve bundle path for metadata check!");
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
    else if class == StoryParamChangeEffect::class() {
        StoryParamChangeEffect::on_LoadAsset
    }
    else {
        return;
    };

    handler(bundle, asset, unsafe { (*name).as_utf16str() });
}

type LoadFromFileInternalFn = extern "C" fn(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject;
extern "C" fn LoadFromFile_Internal(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject {
    get_orig_fn!(LoadFromFile_Internal, LoadFromFileInternalFn)(path, crc, offset)
}

pub fn LoadFromFile_Internal_orig(path: *mut Il2CppString, crc: u32, offset: u64) -> *mut Il2CppObject {
    LoadFromFile_Internal(path, crc, offset)
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

    new_hook!(LoadAsset_Internal_addr, LoadAsset_Internal);
    new_hook!(LoadAssetAsync_Internal_addr, LoadAssetAsync_Internal);
    new_hook!(LoadFromFile_Internal_addr, LoadFromFile_Internal);
}