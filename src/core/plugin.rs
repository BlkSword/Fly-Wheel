//! 插件系统框架
//!
//! 基于动态库(.dll/.so/.dylib)的插件框架，支持运行时加载第三方扩展。
//!
//! 插件类型:
//! - 扫描器插件 (scanner): 自定义端口/服务/主机扫描方法
//! - 收集器插件 (collector): 自定义系统信息收集器
//! - PoC 插件 (poc): 自定义漏洞检测规则
//! - 爆破器插件 (cracker): 自定义密码爆破服务
//!
//! 插件接口:
//! 每个插件导出以下 C ABI 函数:
//! - `plugin_init()` → 返回插件元数据
//! - `plugin_run()` → 执行插件
//! - `plugin_free()` → 释放资源

use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// 插件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginType {
    /// 扫描器插件
    Scanner,
    /// 信息收集器插件
    Collector,
    /// PoC 插件
    Poc,
    /// 爆破器插件
    Cracker,
    /// 输出格式化插件
    Output,
    /// 通用工具插件
    Utility,
}

impl PluginType {
    pub fn as_str(&self) -> &str {
        match self {
            PluginType::Scanner => "scanner",
            PluginType::Collector => "collector",
            PluginType::Poc => "poc",
            PluginType::Cracker => "cracker",
            PluginType::Output => "output",
            PluginType::Utility => "utility",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "scanner" => Some(PluginType::Scanner),
            "collector" => Some(PluginType::Collector),
            "poc" => Some(PluginType::Poc),
            "cracker" => Some(PluginType::Cracker),
            "output" => Some(PluginType::Output),
            "utility" => Some(PluginType::Utility),
            _ => None,
        }
    }
}

/// 插件元数据（插件导出）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMeta {
    /// 插件唯一标识
    pub id: String,
    /// 插件名称（人类可读）
    pub name: String,
    /// 插件版本
    pub version: String,
    /// 插件类型
    pub plugin_type: PluginType,
    /// 作者
    pub author: String,
    /// 描述
    pub description: String,
    /// 所需的最低 IntraSweep 版本
    pub min_intrasweep_version: String,
    /// 依赖的其他插件 ID（可选）
    pub dependencies: Vec<String>,
    /// 标签
    pub tags: Vec<String>,
}

impl PluginMeta {
    /// 创建新的插件元数据
    pub fn new(id: &str, name: &str, plugin_type: PluginType) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            plugin_type,
            author: String::new(),
            description: String::new(),
            min_intrasweep_version: "0.3.0".to_string(),
            dependencies: vec![],
            tags: vec![],
        }
    }

    pub fn with_author(mut self, author: &str) -> Self {
        self.author = author.to_string();
        self
    }

    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = desc.to_string();
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

/// 插件运行结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    /// 是否成功
    pub success: bool,
    /// 输出消息
    pub message: String,
    /// JSON 格式的输出数据
    pub data: Option<String>,
    /// 错误信息（如果失败）
    pub error: Option<String>,
    /// 执行耗时 (ms)
    pub elapsed_ms: u64,
}

impl PluginResult {
    pub fn ok(message: &str) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: None,
            error: None,
            elapsed_ms: 0,
        }
    }

    pub fn ok_with_data(message: &str, data: String) -> Self {
        Self {
            success: true,
            message: message.to_string(),
            data: Some(data),
            error: None,
            elapsed_ms: 0,
        }
    }

    pub fn error(message: &str, error: &str) -> Self {
        Self {
            success: false,
            message: message.to_string(),
            data: None,
            error: Some(error.to_string()),
            elapsed_ms: 0,
        }
    }
}

/// 已加载的插件实例
#[derive(Debug)]
pub struct LoadedPlugin {
    /// 插件元数据
    pub meta: PluginMeta,
    /// 库文件路径
    pub path: PathBuf,
    /// 加载时间
    pub loaded_at: chrono::DateTime<chrono::Utc>,
}

/// 插件管理器
pub struct PluginManager {
    /// 已加载的插件
    plugins: Vec<LoadedPlugin>,
    /// 插件搜索路径
    search_paths: Vec<PathBuf>,
}

impl PluginManager {
    /// 创建新的插件管理器
    pub fn new() -> Self {
        let mut search_paths = Vec::new();

        // 默认搜索路径
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                search_paths.push(dir.join("plugins"));
            }
        }
        search_paths.push(PathBuf::from("./plugins"));

        Self {
            plugins: Vec::new(),
            search_paths,
        }
    }

    /// 添加搜索路径
    pub fn add_search_path(&mut self, path: PathBuf) {
        self.search_paths.push(path);
    }

    /// 发现可用插件
    pub fn discover(&self) -> Vec<PluginMeta> {
        let mut found = Vec::new();
        let lib_ext = if cfg!(windows) { "dll" } else if cfg!(target_os = "macos") { "dylib" } else { "so" };

        for search_path in &self.search_paths {
            if !search_path.exists() {
                continue;
            }

            // 查找插件元数据文件 (.plugin.json)
            if let Ok(entries) = std::fs::read_dir(search_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "json" {
                            let stem = path.file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("");

                            // 检查对应的库文件是否存在
                            let lib_path = search_path.join(format!(
                                "{}.{}",
                                stem.trim_end_matches(".plugin"),
                                lib_ext
                            ));

                            if lib_path.exists() {
                                // 读取元数据
                                if let Ok(content) = std::fs::read_to_string(&path) {
                                    if let Some(meta) = PluginMeta::from_json(&content) {
                                        found.push(meta);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        found
    }

    /// 通过 ID 查找已加载插件
    pub fn get_plugin(&self, id: &str) -> Option<&LoadedPlugin> {
        self.plugins.iter().find(|p| p.meta.id == id)
    }

    /// 获取所有已加载插件的元数据
    pub fn list_plugins(&self) -> Vec<&PluginMeta> {
        self.plugins.iter().map(|p| &p.meta).collect()
    }

    /// 以纯 Rust 方式注册内置"插件"（供内置模块模拟插件接口）
    pub fn register_inline(&mut self, meta: PluginMeta) {
        self.plugins.push(LoadedPlugin {
            meta,
            path: PathBuf::from("<builtin>"),
            loaded_at: chrono::Utc::now(),
        });
    }

    /// 已加载插件数量
    pub fn loaded_count(&self) -> usize {
        self.plugins.len()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成插件元数据模板文件
pub fn generate_plugin_template(id: &str, name: &str, plugin_type: PluginType, output_dir: &Path) -> std::io::Result<PathBuf> {
    let meta = PluginMeta::new(id, name, plugin_type)
        .with_author("Your Name")
        .with_description("插件描述");

    let json_path = output_dir.join(format!("{}.plugin.json", id));
    std::fs::write(&json_path, meta.to_json())?;

    // 同时生成一个 Rust 插件模板
    let rs_path = output_dir.join(format!("{}.rs", id.replace('-', "_")));
    let rs_template = generate_rust_template(&meta);
    std::fs::write(&rs_path, rs_template)?;

    Ok(json_path)
}

/// 生成 Rust 插件模板代码
fn generate_rust_template(meta: &PluginMeta) -> String {
    format!(
        "// {name} 插件 - {desc}\n\
         //\n\
         // 作者: {author}\n\
         // 版本: {version}\n\n\
         use std::ffi::{{c_char, CStr, CString}};\n\n\
         #[repr(C)]\n\
         pub struct PluginInfo {{\n\
             pub id: *const c_char,\n\
             pub name: *const c_char,\n\
             pub version: *const c_char,\n\
             pub plugin_type: *const c_char,\n\
         }}\n\n\
         #[no_mangle]\n\
         pub extern \"C\" fn plugin_init() -> *mut PluginInfo {{\n\
             let info = Box::new(PluginInfo {{\n\
                 id: CString::new(\"{id}\").unwrap().into_raw(),\n\
                 name: CString::new(\"{name}\").unwrap().into_raw(),\n\
                 version: CString::new(\"{version}\").unwrap().into_raw(),\n\
                 plugin_type: CString::new(\"{ptype}\").unwrap().into_raw(),\n\
             }});\n\
             Box::into_raw(info)\n\
         }}\n\n\
         #[no_mangle]\n\
         pub extern \"C\" fn plugin_run(input: *const c_char) -> *mut c_char {{\n\
             if input.is_null() {{\n\
                 return CString::new(\"{{\\\"success\\\": false}}\").unwrap().into_raw();\n\
             }}\n\
             let _input_str = unsafe {{ CStr::from_ptr(input) }}.to_string_lossy();\n\
             let output = \"{{\\\"success\\\": true, \\\"message\\\": \\\"executed\\\"}}\";\n\
             CString::new(output).unwrap().into_raw()\n\
         }}\n\n\
         #[no_mangle]\n\
         pub extern \"C\" fn plugin_free_string(s: *mut c_char) {{\n\
             if !s.is_null() {{ unsafe {{ drop(CString::from_raw(s)); }} }}\n\
         }}\n\n\
         #[no_mangle]\n\
         pub extern \"C\" fn plugin_free_info(info: *mut PluginInfo) {{\n\
             if !info.is_null() {{\n\
                 unsafe {{\n\
                     let info = Box::from_raw(info);\n\
                     drop(CString::from_raw(info.id as *mut c_char));\n\
                     drop(CString::from_raw(info.name as *mut c_char));\n\
                     drop(CString::from_raw(info.version as *mut c_char));\n\
                     drop(CString::from_raw(info.plugin_type as *mut c_char));\n\
                 }}\n\
             }}\n\
         }}\n",
        name = meta.name,
        desc = meta.description,
        author = meta.author,
        version = meta.version,
        id = meta.id,
        ptype = meta.plugin_type.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_meta_creation() {
        let meta = PluginMeta::new("test-plugin", "测试插件", PluginType::Poc)
            .with_author("Test Author")
            .with_description("这是一个测试插件");

        assert_eq!(meta.id, "test-plugin");
        assert_eq!(meta.name, "测试插件");
        assert_eq!(meta.plugin_type, PluginType::Poc);
        assert_eq!(meta.author, "Test Author");
    }

    #[test]
    fn test_plugin_meta_json_roundtrip() {
        let meta = PluginMeta::new("json-test", "JSON测试", PluginType::Scanner)
            .with_author("Dev")
            .with_description("测试序列化");

        let json = meta.to_json();
        let parsed = PluginMeta::from_json(&json).expect("应能解析");

        assert_eq!(parsed.id, "json-test");
        assert_eq!(parsed.name, "JSON测试");
    }

    #[test]
    fn test_plugin_type_from_str() {
        assert_eq!(PluginType::from_str("scanner"), Some(PluginType::Scanner));
        assert_eq!(PluginType::from_str("SCANNER"), Some(PluginType::Scanner));
        assert_eq!(PluginType::from_str("collector"), Some(PluginType::Collector));
        assert_eq!(PluginType::from_str("poc"), Some(PluginType::Poc));
        assert_eq!(PluginType::from_str("cracker"), Some(PluginType::Cracker));
        assert_eq!(PluginType::from_str("invalid"), None);
    }

    #[test]
    fn test_plugin_manager_default() {
        let manager = PluginManager::new();
        assert_eq!(manager.loaded_count(), 0);
        assert!(!manager.search_paths.is_empty());
    }

    #[test]
    fn test_plugin_manager_register_inline() {
        let mut manager = PluginManager::new();
        let meta = PluginMeta::new("inline-plugin", "内置插件", PluginType::Utility);
        manager.register_inline(meta);
        assert_eq!(manager.loaded_count(), 1);
        assert!(manager.get_plugin("inline-plugin").is_some());
    }

    #[test]
    fn test_plugin_result_ok() {
        let result = PluginResult::ok("成功");
        assert!(result.success);
        assert_eq!(result.message, "成功");
        assert!(result.error.is_none());
    }

    #[test]
    fn test_plugin_result_error() {
        let result = PluginResult::error("失败", "详细错误信息");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_plugin_result_with_data() {
        let result = PluginResult::ok_with_data("完成", r#"{"count": 42}"#.to_string());
        assert!(result.success);
        assert_eq!(result.data, Some(r#"{"count": 42}"#.to_string()));
    }

    #[test]
    fn test_generate_plugin_template() {
        let dir = std::env::temp_dir();
        let result = generate_plugin_template(
            "my-plugin",
            "我的插件",
            PluginType::Poc,
            &dir,
        );
        assert!(result.is_ok());

        let json_path = result.unwrap();
        let content = std::fs::read_to_string(&json_path).expect("读取模板");
        assert!(content.contains("my-plugin"));
        assert!(content.contains("我的插件"));

        let _ = std::fs::remove_file(&json_path);
    }
}
