#![allow(non_snake_case)]

use std::{path::Path, sync::atomic::{AtomicBool, Ordering}};

use windows::{core::{w, PCWSTR}, Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleHandleW}};

use crate::{core::{Error, Hachimi}, windows::{steamworks, utils}};

use super::{hachimi_impl, proxy, ffi};

// Global flag to track if this is a late loading scenario
static IS_LATE_LOADING: AtomicBool = AtomicBool::new(false);

pub fn is_late_loading() -> bool {
    IS_LATE_LOADING.load(Ordering::Relaxed)
}

type LoadLibraryWFn = extern "C" fn(filename: PCWSTR) -> HMODULE;
extern "C" fn LoadLibraryW(filename: PCWSTR) -> HMODULE {
    let hachimi = Hachimi::instance();
    let orig_fn: LoadLibraryWFn = unsafe {
        std::mem::transmute(hachimi.interceptor.get_trampoline_addr(LoadLibraryW as *const () as usize))
    };

    let handle = orig_fn(filename);
    let filename_str = unsafe { filename.to_string().expect("valid utf-16 filename") };

    if hachimi_impl::is_criware_lib(&filename_str) {
        // Manually trigger a GameAssembly.dll load anyways since hachimi might have been loaded later
        let assembly_module = orig_fn(w!("GameAssembly.dll")).0 as usize;
        if assembly_module != 0 {
            hachimi.on_dlopen("GameAssembly.dll", assembly_module);
        }
    }

    let needs_init_steamworks = steamworks::is_overlay_conflicting(&hachimi);
    if hachimi.on_dlopen(&filename_str, handle.0 as usize) {
        if !needs_init_steamworks {
            hachimi.interceptor.unhook(LoadLibraryW as *const () as usize);
        }
    }
    else if needs_init_steamworks &&
        Path::new(&filename_str).file_name().is_some_and(|name| name == "steam_api64.dll")
    {
        steamworks::init(handle);
        hachimi.interceptor.unhook(LoadLibraryW as *const () as usize);
    }
    handle
}

fn init_internal() -> Result<(), Error> {
    let hachimi = Hachimi::instance();
    if let Ok(handle) = unsafe { GetModuleHandleW(w!("GameAssembly.dll")) } {
        info!("Late loading detected");
        IS_LATE_LOADING.store(true, Ordering::Relaxed);
        
        // When late loaded (e.g., by localify), skip all proxy and hook initialization
        // Other DLL (like localify) may have already hooked LoadLibraryW
        info!("Skipping LoadLibraryW hook (late loading mode)");
        info!("Skipping DLL proxy initialization (late loading mode)");

        hachimi.on_dlopen("GameAssembly.dll", handle.0 as _);
        hachimi.on_hooking_finished();   
    }
    else {
        info!("Init UnityPlayer.dll proxy");
        proxy::unityplayer::init();

        let system_dir = utils::_get_system_directory();

        info!("Init winhttp.dll proxy");
        proxy::winhttp::init(&system_dir);

        info!("Hooking LoadLibraryW");
        hachimi.interceptor.hook(ffi::LoadLibraryW as *const () as usize, LoadLibraryW as *const () as usize)?;
    }

    Ok(())
}

pub fn init() {
    init_internal().unwrap_or_else(|e| {
        error!("Init failed: {}", e);
    });
}