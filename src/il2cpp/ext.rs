use std::{fs, hash::Hasher, path::PathBuf, sync::Mutex};

use fnv::{FnvHasher, FnvHashMap};
use once_cell::sync::Lazy;
use widestring::{Utf16Str, Utf16String};

use crate::core::hachimi::{Hachimi, LocalizedData};

use super::{
    api::il2cpp_string_new_utf16,
    hook::{
        UnityEngine_AssetBundleModule::AssetBundle,
        UnityEngine_CoreModule::{HideFlags_DontUnloadUnusedAsset, Object},
        UnityEngine_TextRenderingModule::Font, Unity_TextMeshPro::TMP_FontAsset
    },
    symbols::GCHandle,
    types::*
};

pub trait StringExt {
    fn to_il2cpp_string(&self) -> *mut Il2CppString;
}

impl StringExt for str {
    fn to_il2cpp_string(&self) -> *mut Il2CppString {
        let text_utf16 = Utf16String::from_str(self);
        il2cpp_string_new_utf16(text_utf16.as_ptr(), text_utf16.len().try_into().unwrap())
    }
}

impl StringExt for String {
    fn to_il2cpp_string(&self) -> *mut Il2CppString {
        str::to_il2cpp_string(self)
    }
}

pub trait LocalizedDataExt {
    fn load_extra_asset_bundle(&self) -> *mut Il2CppObject;
    fn load_replacement_font(&self) -> *mut Il2CppObject;
    fn load_tmp_replacement_font(&self) -> *mut Il2CppObject;
    fn load_mods_asset_bundles(&self) -> FnvHashMap<String, *mut Il2CppObject>;
    fn get_mod_asset_bundle(&self, name: &str) -> *mut Il2CppObject;
}

static EXTRA_ASSET_BUNDLE_HANDLE: Lazy<Mutex<Option<GCHandle>>> = Lazy::new(|| Mutex::default());
static CUSTOM_FONT_BUNDLE_HANDLE: Lazy<Mutex<Option<GCHandle>>> = Lazy::new(|| Mutex::default());
static CUSTOM_FONT_SOURCE: Lazy<Mutex<Option<(String, String)>>> = Lazy::new(|| Mutex::default());
static CUSTOM_FONT_LOAD_ATTEMPTED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));
static CUSTOM_TMP_FONT_LOAD_ATTEMPTED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));
static REPLACEMENT_FONT_HANDLE: Lazy<Mutex<Option<GCHandle>>> = Lazy::new(|| Mutex::default());
static TMP_REPLACEMENT_FONT_HANDLE: Lazy<Mutex<Option<GCHandle>>> = Lazy::new(|| Mutex::default());
static MODS_ASSET_BUNDLE_HANDLES: Lazy<Mutex<FnvHashMap<String, GCHandle>>> = Lazy::new(|| Mutex::default());
static MODS_BUNDLES_LOADED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

fn custom_font_source() -> Option<(String, String)> {
    let config = Hachimi::instance().config.load();
    config.custom_font_asset_bundle.as_deref()
        .filter(|path| !path.trim().is_empty())
        .zip(config.custom_font_name.as_deref().filter(|name| !name.trim().is_empty()))
        .map(|(path, name)| {
            (
                path.trim().to_owned(),
                name.trim().replace('\\', "/").to_lowercase()
            )
        })
}

fn sync_custom_font_source(source: &Option<(String, String)>) {
    let mut cached_source = CUSTOM_FONT_SOURCE.lock().unwrap();
    if *cached_source != *source {
        *CUSTOM_FONT_BUNDLE_HANDLE.lock().unwrap() = None;
        *REPLACEMENT_FONT_HANDLE.lock().unwrap() = None;
        *TMP_REPLACEMENT_FONT_HANDLE.lock().unwrap() = None;
        *CUSTOM_FONT_LOAD_ATTEMPTED.lock().unwrap() = false;
        *CUSTOM_TMP_FONT_LOAD_ATTEMPTED.lock().unwrap() = false;
        *cached_source = source.clone();
    }
}

impl LocalizedDataExt for LocalizedData {
    fn load_extra_asset_bundle(&self) -> *mut Il2CppObject {
        let mut handle_opt = EXTRA_ASSET_BUNDLE_HANDLE.lock().unwrap();
        if let Some(handle) = handle_opt.as_ref() {
            return handle.target();
        }

        let Some(path) = self.config.extra_asset_bundle.as_ref().map(|p| self.get_data_path(p)).unwrap_or_default() else {
            return 0 as _;
        };

        let Some(path_str) = path.to_str() else {
            error!("Invalid extra asset bundle path");
            return 0 as _;
        };

        let bundle = AssetBundle::LoadFromFile_Internal_orig(path_str.to_il2cpp_string(), 0, 0);
        if bundle.is_null() {
            error!("Failed to load extra asset bundle");
            return 0 as _;
        }

        *handle_opt = Some(GCHandle::new(bundle, false));
        bundle
    }

    fn load_replacement_font(&self) -> *mut Il2CppObject {
        let custom_source = custom_font_source();
        sync_custom_font_source(&custom_source);

        {
            let mut handle_opt = REPLACEMENT_FONT_HANDLE.lock().unwrap();
            if let Some(handle) = handle_opt.as_ref() {
                let font = handle.target();
                if Object::IsNativeObjectAlive(font) {
                    return font;
                }
                else {
                    debug!("Font destroyed!");
                    *handle_opt = None;
                }
            }
        }

        if custom_source.is_some() {
            let mut attempted = CUSTOM_FONT_LOAD_ATTEMPTED.lock().unwrap();
            if *attempted {
                return 0 as _;
            }
            *attempted = true;
        }

        let (bundle, name) = if let Some((path, name)) = custom_source {
            let cached_bundle = CUSTOM_FONT_BUNDLE_HANDLE.lock().unwrap()
                .as_ref().map(|handle| handle.target());
            let bundle = if let Some(bundle) = cached_bundle {
                bundle
            }
            else {
                let path = Hachimi::instance().get_data_path(path);
                let Some(path_str) = path.to_str() else {
                    error!("Invalid custom font asset bundle path");
                    return 0 as _;
                };
                info!("Loading custom font AssetBundle: {}", path.display());
                let bundle = AssetBundle::LoadFromFile_Internal_orig(path_str.to_il2cpp_string(), 0, 0);
                if bundle.is_null() {
                    error!("Failed to load custom font asset bundle: {}", path.display());
                    return 0 as _;
                }
                *CUSTOM_FONT_BUNDLE_HANDLE.lock().unwrap() = Some(GCHandle::new(bundle, false));
                bundle
            };
            (bundle, name)
        } else {
            let Some(name) = &self.config.replacement_font_name else {
                return 0 as _;
            };
            (self.load_extra_asset_bundle(), name.to_owned())
        };
        if bundle.is_null() {
            return 0 as _;
        }

        if custom_font_source().is_some() {
            info!("Loading custom font asset: {name}");
        }
        let font = AssetBundle::LoadAsset_Internal_orig(bundle, name.to_il2cpp_string(), Font::type_object());
        if font.is_null() {
            error!("Failed to load replacement font asset: {name}");
            return 0 as _;
        }
        Object::set_hideFlags(font, HideFlags_DontUnloadUnusedAsset);

        *REPLACEMENT_FONT_HANDLE.lock().unwrap() = Some(GCHandle::new(font, false));
        font
    }

    fn load_tmp_replacement_font(&self) -> *mut Il2CppObject {
        sync_custom_font_source(&custom_font_source());

        {
            let mut handle_opt = TMP_REPLACEMENT_FONT_HANDLE.lock().unwrap();
            if let Some(handle) = handle_opt.as_ref() {
                let tmp_font = handle.target();
                if Object::IsNativeObjectAlive(tmp_font) {
                    return tmp_font;
                }
                else {
                    debug!("TMP font destroyed!");
                    *handle_opt = None;
                }
            }
        }

        let font = self.load_replacement_font();
        if font.is_null() {
            return 0 as _;
        }

        if custom_font_source().is_some() {
            let mut attempted = CUSTOM_TMP_FONT_LOAD_ATTEMPTED.lock().unwrap();
            if *attempted {
                return 0 as _;
            }
            *attempted = true;
        }

        let tmp_font = TMP_FontAsset::CreateFontAsset(font);
        if tmp_font.is_null() {
            error!("Failed to create TMP font");
            return 0 as _;
        }
        Object::set_hideFlags(tmp_font, HideFlags_DontUnloadUnusedAsset);

        *TMP_REPLACEMENT_FONT_HANDLE.lock().unwrap() = Some(GCHandle::new(tmp_font, false));
        tmp_font
    }

    fn load_mods_asset_bundles(&self) -> FnvHashMap<String, *mut Il2CppObject> {
        // 检查是否已经加载过
        let mut loaded = MODS_BUNDLES_LOADED.lock().unwrap();
        if *loaded {
            // 已经加载过，直接返回缓存的结果
            let handles = MODS_ASSET_BUNDLE_HANDLES.lock().unwrap();
            let mut result = FnvHashMap::default();
            for (name, handle) in handles.iter() {
                let bundle = handle.target();
                if !bundle.is_null() {
                    result.insert(name.clone(), bundle);
                }
            }
            return result;
        }

        println!("Starting to load mods asset bundles...");
        let mut handles = MODS_ASSET_BUNDLE_HANDLES.lock().unwrap();
        let mut result = FnvHashMap::default();

        // 扫描 mods 文件夹 - 使用 Hachimi 数据目录而不是 localized_data 目录
        use crate::core::Hachimi;
        let mods_path = Some(Hachimi::instance().get_data_path("mods"));
        let bundle_files = LocalizedData::scan_asset_bundle_files(&mods_path);
        
        println!("Found {} potential asset bundle files", bundle_files.len());

        for (name, path) in bundle_files {
            // 加载 AssetBundle - 使用 to_string_lossy 支持 Unicode 路径
            let path_str = path.to_string_lossy();
            if path_str.is_empty() {
                println!("Empty asset bundle path for '{}': {:?}", name, path);
                continue;
            }

            let il2cpp_string = path_str.as_ref().to_il2cpp_string();
            let bundle = AssetBundle::LoadFromFile_Internal_orig(il2cpp_string, 0, 0);
            if bundle.is_null() {
                println!("Failed to load asset bundle '{}' from: {}", name, path_str);
                continue;
            }

            println!("Loaded mod asset bundle: '{}'", name);
            
            // 缓存句柄
            let handle = GCHandle::new(bundle, false);
            handles.insert(name.clone(), handle);
            result.insert(name, bundle);
        }

        // 标记为已加载
        *loaded = true;
        drop(loaded);
        drop(handles);
        
        println!("Finished loading {} mod asset bundles", result.len());
        result
    }

    fn get_mod_asset_bundle(&self, name: &str) -> *mut Il2CppObject {
        let bundles = self.load_mods_asset_bundles();
        bundles.get(name).copied().unwrap_or(std::ptr::null_mut())
    }
}

impl LocalizedData {
    /// 扫描指定目录及其子目录，查找所有无扩展名的文件（AssetBundle 文件）
    fn scan_asset_bundle_files(mods_path: &Option<PathBuf>) -> FnvHashMap<String, PathBuf> {
        let mut bundle_files = FnvHashMap::default();
        
        println!("Scanning for asset bundle files...");
        
        // Try the exact path first (hard-coded based on the error message)
        let exact_mods_path = PathBuf::from(r"E:\Documents\Umamusume\hachimi\mods");
        
        if exact_mods_path.exists() && exact_mods_path.is_dir() {
            println!("Using exact mods folder path: {:?}", exact_mods_path);
            
            if let Err(e) = Self::scan_directory_recursive(&exact_mods_path, &mut bundle_files) {
                println!("Failed to scan mods directory: {}", e);
            }
            
            if !bundle_files.is_empty() {
                println!("Found {} files in exact path", bundle_files.len());
                return bundle_files;
            }
        } else {
            println!("Exact path does not exist: {:?}", exact_mods_path);
        }
        
        // Fallback to the original method
        let Some(mods_path) = mods_path else {
            println!("No fallback mods path provided");
            return bundle_files;
        };

        println!("Trying fallback mods path: {:?}", mods_path);
        
        if !mods_path.exists() {
            println!("Fallback mods path does not exist: {:?}", mods_path);
            return bundle_files;
        }

        if let Err(e) = Self::scan_directory_recursive(mods_path, &mut bundle_files) {
            println!("Failed to scan fallback mods directory: {}", e);
        }

        println!("Found {} files in fallback path", bundle_files.len());
        bundle_files
    }

    /// 递归扫描目录，查找无扩展名的文件
    fn scan_directory_recursive(dir: &PathBuf, bundle_files: &mut FnvHashMap<String, PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
        println!("Scanning directory: {:?}", dir);
        let entries = fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                println!("Found subdirectory: {:?}", path);
                // 递归扫描子目录
                Self::scan_directory_recursive(&path, bundle_files)?;
            } else if path.is_file() {
                // 检查是否为无扩展名的文件
                let extension = path.extension();
                
                println!("Found file: {:?}, extension: {:?}", path, extension);
                
                if extension.is_none() {
                    // 使用 to_string_lossy 来支持 Unicode 字符（包括中文）
                    let file_name = path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "unknown".to_string());
                    
                    // 使用文件的相对路径作为键，以避免重名冲突
                    let relative_key = if let Ok(relative_path) = path.strip_prefix(dir.parent().unwrap_or(dir)) {
                        relative_path.to_string_lossy().replace('\\', "/")
                    } else {
                        file_name.clone()
                    };
                    
                    println!("Found asset bundle file: {} -> {:?}", relative_key, path);
                    bundle_files.insert(relative_key, path);
                }
            }
        }

        Ok(())
    }
}

pub trait Il2CppStringExt {
    fn chars_ptr(&self) -> *const Il2CppChar;
    fn as_utf16str(&self) -> &Utf16Str;
    fn hash(&self) -> u64;
}

impl Il2CppStringExt for Il2CppString {
    fn chars_ptr(&self) -> *const Il2CppChar {
        self.chars.as_ptr()
    }

    fn as_utf16str(&self) -> &Utf16Str {
        unsafe { Utf16Str::from_slice_unchecked(std::slice::from_raw_parts(self.chars.as_ptr(), self.length as usize)) }
    }

    fn hash(&self) -> u64 {
        let data = self.chars_ptr() as *const u8;
        let len = self.length as usize * std::mem::size_of::<Il2CppChar>();
        
        let mut hasher = FnvHasher::default();
        hasher.write(unsafe { std::slice::from_raw_parts(data, len) });
        hasher.finish()
    }
}

pub trait Il2CppObjectExt {
    fn klass(&self) -> *mut Il2CppClass;
}

impl Il2CppObjectExt for Il2CppObject {
    fn klass(&self) -> *mut Il2CppClass {
        unsafe { *self.__bindgen_anon_1.klass.as_ref() }
    }
}