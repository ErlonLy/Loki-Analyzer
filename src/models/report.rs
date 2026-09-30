use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionItem {
    pub category: String, // "Protector", "Anti-Cheat", "Compiler", "Packer", "Engine", "Crypto"
    pub name: String,
    pub version: Option<String>,
    pub details: String,
    pub confidence: u8,   // 0-100%
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub path: String,
    pub filename: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub format: String, // "PE32", "PE32+", "ELF", "Mach-O", "Driver (SYS)", "DLL", "Raw"
    pub architecture: String, // "x86", "x86_64", "ARM64", "CLR/.NET", "Unknown"
    pub is_64bit: bool,
    pub is_dotnet: bool,
    pub is_driver: bool,
    pub is_signed: bool,
    pub subsystem: String,
    pub entry_point: u64,
    pub overall_entropy: f64,
    pub compiler: Option<String>,
    pub linker: Option<String>,
    pub possible_language: String,
    pub protectors: Vec<String>,
    pub detections: Vec<DetectionItem>,
    pub sections: Vec<SectionInfo>,
    pub imports_count: usize,
    pub imported_dlls: Vec<String>,
    pub exports_count: usize,
    pub suspicious_imports: Vec<String>,
    pub crypto_constants: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCheatSummary {
    pub detected: bool,
    pub name: String,
    pub vendor: String,
    pub version: Option<String>,
    pub driver_file: Option<String>,
    pub service_name: Option<String>,
    pub protection_type: String, // "Kernel-Level (Ring 0)", "User-Mode (Ring 3)", "Hybrid", "DRM / Server"
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub app_name: String,
    pub target_path: String,
    pub target_type: String, // "Game", "Software/Application", "Driver/System", "Single File"
    pub scan_time: String,
    pub scan_duration_ms: u128,
    pub total_files_scanned: usize,
    pub binary_files_analyzed: usize,
    pub game_engine: Option<String>,
    pub anticheats: Vec<AntiCheatSummary>,
    pub protectors_detected: Vec<String>,
    pub protections_found: Vec<String>,
    pub compilers_detected: Vec<String>,
    pub languages_detected: Vec<String>,
    pub middlewares_detected: Vec<String>,
    pub crypto_algorithms: Vec<String>,
    pub files: Vec<FileAnalysis>,
    pub summary_stats: ScanSummaryStats,
}


#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummaryStats {
    pub total_executables: usize,
    pub total_dlls: usize,
    pub total_drivers: usize,
    pub packed_count: usize,
    pub high_entropy_count: usize,
    pub average_entropy: f64,
    pub max_entropy: f64,
}
