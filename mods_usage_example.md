# AssetBundle自动扫描和替换功能使用说明

## 功能概述

Hachimi 现在支持自动扫描 `mods` 文件夹中的所有 AssetBundle 文件，并在游戏运行时自动替换相应的资源。这个功能让你可以更方便地添加模组，无需手动配置每个 AssetBundle。

## 工作原理

1. **自动扫描**：启动时自动扫描 `mods` 文件夹（包括子文件夹）中所有无扩展名的文件
2. **自动加载**：将找到的文件尝试作为 Unity AssetBundle 加载
3. **运行时替换**：当游戏尝试加载任何资源时，系统会：
   - 首先检查 mods AssetBundle 中是否有同名资源
   - 如果找到，使用 mods 版本的资源
   - 如果没找到，使用游戏原始资源

## 目录结构示例

```
Hachimi 数据目录/
├── config.json
├── mods/                  # 直接在数据目录下，不在 localized_data 中
│   ├── ui_bundle          # 无扩展名文件，会被自动加载
│   ├── fonts/
│   │   ├── custom_font    # 子文件夹中的无扩展名文件也会被加载
│   │   └── font.ttf       # 有扩展名的文件会被忽略
│   ├── textures/
│   │   ├── background     # 会被加载
│   │   └── sprite         # 会被加载
│   ├── 中文文件夹/          # ✅ 支持中文文件夹名
│   │   ├── 界面资源         # ✅ 支持中文文件名
│   │   └── 图标           # ✅ 支持中文文件名
│   ├── 日本語/            # ✅ 支持日文
│   │   └── ui_jp         
│   └── sounds/
│       ├── bgm            # 会被加载
│       └── readme.txt     # 有扩展名，会被忽略
└── localized_data/        # 本地化数据在这里，但 mods 不在这个目录
    ├── config.json
    └── ...
```

## 代码使用方法

### 1. 加载所有 Mod AssetBundles

```rust
use crate::il2cpp::ext::LocalizedDataExt;

// 获取所有已加载的 mod AssetBundles
let bundles = localized_data.load_mods_asset_bundles();
for (name, bundle_ptr) in bundles {
    info!("Loaded mod bundle: {}", name);
    // 使用 bundle_ptr 进行后续操作
}
```

### 2. 获取特定名称的 AssetBundle

```rust
// 获取特定的 mod AssetBundle
let ui_bundle = localized_data.get_mod_asset_bundle("mods/ui_bundle");
if !ui_bundle.is_null() {
    // 使用这个 AssetBundle 加载资源
    let sprite = AssetBundle::LoadAsset_Internal_orig(
        ui_bundle, 
        "my_sprite".to_il2cpp_string(), 
        SomeType::type_object()
    );
}

// 使用相对路径获取子文件夹中的资源
let font_bundle = localized_data.get_mod_asset_bundle("mods/fonts/custom_font");
```

### 3. 在现有代码中集成

可以修改现有的资源加载逻辑，优先从 mods 中查找资源：

```rust
impl SomeResourceLoader {
    fn load_custom_sprite(&self, sprite_name: &str) -> *mut Il2CppObject {
        // 首先尝试从 mods 中加载
        let mod_bundles = self.localized_data.load_mods_asset_bundles();
        for (_, bundle) in mod_bundles {
            let sprite = AssetBundle::LoadAsset_Internal_orig(
                bundle, 
                sprite_name.to_il2cpp_string(), 
                Sprite::type_object()
            );
            if !sprite.is_null() {
                return sprite;
            }
        }
        
        // 如果 mods 中没有找到，使用默认逻辑
        self.load_default_sprite(sprite_name)
    }
}
```

## 特性说明

1. **自动缓存**: 已加载的 AssetBundle 会被缓存，避免重复加载
2. **递归扫描**: 支持扫描 `mods` 文件夹及其所有子文件夹
3. **无扩展名检测**: 只有无扩展名的文件才会被识别为 AssetBundle
4. **路径键**: 使用相对路径作为键，避免不同子文件夹中同名文件的冲突
5. **错误处理**: 对无效文件和加载失败提供详细的错误日志
6. **延迟加载**: 只有在首次调用时才会扫描文件夹
7. **Unicode 支持**: 完全支持中文文件夹和文件名，使用 UTF-8 编码处理路径

## 调试信息

默认情况下，为了性能考虑，mods功能的详细调试日志是**关闭**的。如果你需要查看详细的扫描和加载过程，可以在配置文件中启用。

### 启用调试日志

在 `config.json` 中添加：
```json
{
  "enable_mods_debug_logs": true
}
```

### 调试日志示例

启用调试后，你会看到详细的控制台输出：

**启动时的扫描过程：**
```
Trying exact mods path: "E:\\Documents\\Umamusume\\hachimi\\mods"
Using exact mods folder path: "E:\\Documents\\Umamusume\\hachimi\\mods"
Scanning directory: "E:\\Documents\\Umamusume\\hachimi\\mods"
Found entry: "E:\\Documents\\Umamusume\\hachimi\\mods\\你的模组文件"
  -> File
  -> Extension: None
  -> No extension found! This is a potential asset bundle
  -> Adding asset bundle: mods/你的模组文件 -> "E:\\Documents\\Umamusume\\hachimi\\mods\\你的模组文件"
Found 3 asset bundle file(s) in exact mods directory
Starting to load 3 asset bundle(s)...
Processing asset bundle: 'mods/你的模组文件' -> 'E:\Documents\Umamusume\hachimi\mods\你的模组文件'
  -> Loading from: E:\Documents\Umamusume\hachimi\mods\你的模组文件
  -> IL2CPP string created successfully
  -> SUCCESS: Asset bundle loaded!
Asset bundle loading complete! Loaded 3 bundle(s) successfully.
```

**游戏运行时的资源替换：**
```
Loading asset: 'chara/chr1001/chr_1001_00_01.prefab' from bundle: 0x...
  -> Checking mod bundle: 'mods/你的模组文件' (0x...)
  -> SUCCESS: Found replacement asset in mod bundle 'mods/你的模组文件'!
```

### 性能影响

- **调试日志关闭时**：只输出基本的加载统计信息，对性能影响最小
- **调试日志开启时**：会输出每个文件的详细处理过程，可能影响加载性能

建议在正常使用时关闭调试日志，只在需要排查问题时临时开启。

## 日志输出示例

```
INFO: Mods folder path: "E:\\Documents\\Umamusume\\hachimi\\mods"
Mods folder path: "E:\\Documents\\Umamusume\\hachimi\\mods"
INFO: Mods folder absolute path: "E:\\Documents\\Umamusume\\hachimi\\mods"
Mods folder absolute path: "E:\\Documents\\Umamusume\\hachimi\\mods"
DEBUG: Found asset bundle file: mods/ui_bundle -> E:\Documents\Umamusume\hachimi\mods\ui_bundle
DEBUG: Found asset bundle file: mods/fonts/custom_font -> E:\Documents\Umamusume\hachimi\mods\fonts\custom_font
DEBUG: Found asset bundle file: mods/中文文件夹/界面资源 -> E:\Documents\Umamusume\hachimi\mods\中文文件夹\界面资源
DEBUG: Found asset bundle file: mods/日本語/ui_jp -> E:\Documents\Umamusume\hachimi\mods\日本語\ui_jp
INFO: Found 4 asset bundle file(s) in mods directory
INFO: Loaded mod asset bundle 'mods/ui_bundle' from: E:\Documents\Umamusume\hachimi\mods\ui_bundle
INFO: Loaded mod asset bundle 'mods/fonts/custom_font' from: E:\Documents\Umamusume\hachimi\mods\fonts\custom_font
INFO: Loaded mod asset bundle 'mods/中文文件夹/界面资源' from: E:\Documents\Umamusume\hachimi\mods\中文文件夹\界面资源
INFO: Loaded mod asset bundle 'mods/日本語/ui_jp' from: E:\Documents\Umamusume\hachimi\mods\日本語\ui_jp
```

## 注意事项

1. 确保 AssetBundle 文件是为正确的平台构建的
2. AssetBundle 文件必须是有效的 Unity 格式
3. mods 文件夹会在游戏数据目录下自动创建（如果不存在）
4. 建议使用描述性的文件夹结构来组织不同类型的资源
5. **中文支持**：完全支持中文、日文、韩文等 Unicode 文件夹和文件名
6. **路径编码**：内部使用 UTF-8 编码处理所有路径，确保多语言兼容性