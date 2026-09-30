use crate::engine::entropy::{calculate_entropy, detect_crypto_constants};
use crate::models::report::{DetectionItem, FileAnalysis, SectionInfo};
use goblin::pe::PE;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn analyze(path: &Path, root_path: &Path) -> Result<FileAnalysis, String> {
        let mut file = File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;
        let metadata = file.metadata().map_err(|e| format!("Cannot read metadata: {}", e))?;
        let size_bytes = metadata.len();

        let max_read = if size_bytes > 32 * 1024 * 1024 {
            16 * 1024 * 1024
        } else {
            size_bytes as usize
        };

        let mut buffer = Vec::with_capacity(max_read);
        let mut handle = (&mut file).take(max_read as u64);
        let _ = handle.read_to_end(&mut buffer);

        let sha256 = Self::calculate_sha256(path, size_bytes)?;

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let relative_path = path.strip_prefix(root_path)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let pe_res = PE::parse(&buffer);
        match pe_res {
            Ok(pe) => Self::build_pe_analysis(path, filename, relative_path, size_bytes, sha256, &buffer, &pe),
            Err(_) => Self::build_raw_analysis(path, filename, relative_path, size_bytes, sha256, &buffer),
        }
    }

    fn calculate_sha256(path: &Path, size_bytes: u64) -> Result<String, String> {
        let mut file = File::open(path).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        let max_hash_bytes = if size_bytes > 32 * 1024 * 1024 {
            32 * 1024 * 1024
        } else {
            size_bytes as usize
        };
        let mut total_read = 0;
        let mut chunk = [0u8; 64 * 1024];
        while total_read < max_hash_bytes {
            let to_read = std::cmp::min(chunk.len(), max_hash_bytes - total_read);
            let bytes_read = file.read(&mut chunk[..to_read]).map_err(|e| e.to_string())?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&chunk[..bytes_read]);
            total_read += bytes_read;
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn build_pe_analysis(
        path: &Path,
        filename: String,
        relative_path: String,
        size_bytes: u64,
        sha256: String,
        buffer: &[u8],
        pe: &PE,
    ) -> Result<FileAnalysis, String> {
        let is_64bit = pe.is_64;
        let is_driver = filename.to_lowercase().ends_with(".sys");
        let format = if is_driver {
            "Driver (SYS)".to_string()
        } else if pe.header.coff_header.characteristics & 0x2000 != 0 {
            "DLL".to_string()
        } else if is_64bit {
            "PE32+ (64-bit EXE)".to_string()
        } else {
            "PE32 (32-bit EXE)".to_string()
        };

        let architecture = if is_64bit {
            "x86_64".to_string()
        } else {
            "x86".to_string()
        };

        let subsystem = match pe.header.optional_header {
            Some(opt) => match opt.windows_fields.subsystem {
                1 => "Native",
                2 => "Windows GUI",
                3 => "Windows CUI (Console)",
                7 => "POSIX CUI",
                9 => "Windows CE GUI",
                10 => "EFI Application",
                11 => "EFI Boot Service Driver",
                12 => "EFI Runtime Driver",
                _ => "Unknown Subsystem",
            }.to_string(),
            None => "None".to_string(),
        };

        let entry_point = pe.entry as u64;
        let overall_entropy = calculate_entropy(buffer);

        // Sections
        let mut sections = Vec::new();
        for sec in &pe.sections {
            let sec_name = String::from_utf8_lossy(&sec.name)
                .trim_matches('\0')
                .trim()
                .to_string();

            let sec_offset = sec.pointer_to_raw_data as usize;
            let sec_size = sec.size_of_raw_data as usize;

            let sec_entropy = if sec_offset + sec_size <= buffer.len() && sec_size > 0 {
                calculate_entropy(&buffer[sec_offset..sec_offset + sec_size])
            } else {
                0.0
            };

            let is_executable = (sec.characteristics & 0x20000000) != 0;
            let is_writable = (sec.characteristics & 0x80000000) != 0;

            sections.push(SectionInfo {
                name: sec_name,
                virtual_address: sec.virtual_address,
                virtual_size: sec.virtual_size,
                raw_size: sec.size_of_raw_data,
                entropy: (sec_entropy * 100.0).round() / 100.0,
                characteristics: sec.characteristics,
                is_executable,
                is_writable,
            });
        }

        // Imports
        let mut imported_dlls = Vec::new();
        let mut imports_count = 0;
        let mut suspicious_imports = Vec::new();

        for import in &pe.imports {
            imported_dlls.push(import.dll.to_string());
            imports_count += 1;

            let susp_list = [
                "IsDebuggerPresent",
                "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess",
                "VirtualProtect",
                "VirtualProtectEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "NtSetInformationThread",
                "OutputDebugStringA",
                "OutputDebugStringW",
                "FindWindowA",
                "FindWindowW",
                "GetTickCount",
                "QueryPerformanceCounter",
                "OpenProcess",
            ];

            if susp_list.iter().any(|&s| s.eq_ignore_ascii_case(&import.name)) {
                suspicious_imports.push(format!("{}!{}", import.dll, import.name));
            }
        }
        imported_dlls.sort();
        imported_dlls.dedup();

        let exports_count = pe.exports.len();

        let mut is_dotnet = false;
        let mut compiler = None;
        let mut linker = None;
        let mut possible_language = "C / C++".to_string();
        let mut detections = Vec::new();
        let mut protectors = Vec::new();

        if let Some(opt) = pe.header.optional_header {
            if opt.data_directories.get_clr_runtime_header().is_some() {
                is_dotnet = true;
                possible_language = "C# / .NET".to_string();
                detections.push(DetectionItem {
                    category: "Compiler".to_string(),
                    name: ".NET / C# / CLR".to_string(),
                    version: None,
                    details: "Executable contains Common Language Runtime (CLR) headers".to_string(),
                    confidence: 100,
                });
            }
        }

        // DiE Rules Heuristics & Signature matching
        Self::apply_die_signatures(
            &sections,
            &imported_dlls,
            buffer,
            &mut detections,
            &mut protectors,
            &mut compiler,
            &mut linker,
            &mut possible_language,
        );

        // Crypto constants
        let crypto_constants = detect_crypto_constants(buffer);
        for c in &crypto_constants {
            detections.push(DetectionItem {
                category: "Crypto".to_string(),
                name: c.clone(),
                version: None,
                details: "Cryptographic constant / S-Box signature verified in binary".to_string(),
                confidence: 95,
            });
        }

        let is_signed = pe.header.optional_header
            .map(|opt| {
                if let Some(Some((_, dir))) = opt.data_directories.data_directories.get(4) {
                    dir.virtual_address != 0 && dir.size > 0
                } else {
                    false
                }
            })
            .unwrap_or(false);

        Ok(FileAnalysis {
            path: path.to_string_lossy().to_string(),
            filename,
            relative_path,
            size_bytes,
            sha256,
            format,
            architecture,
            is_64bit,
            is_dotnet,
            is_driver,
            is_signed,
            subsystem,
            entry_point,
            overall_entropy: (overall_entropy * 100.0).round() / 100.0,
            compiler,
            linker,
            possible_language,
            protectors,
            detections,
            sections,
            imports_count,
            imported_dlls,
            exports_count,
            suspicious_imports,
            crypto_constants,
        })
    }

    fn apply_die_signatures(
        sections: &[SectionInfo],
        imported_dlls: &[String],
        buffer: &[u8],
        detections: &mut Vec<DetectionItem>,
        protectors: &mut Vec<String>,
        compiler: &mut Option<String>,
        linker: &mut Option<String>,
        possible_language: &mut String,
    ) {
        let sec_names: Vec<String> = sections.iter().map(|s| s.name.to_lowercase()).collect();

        // 1. VMProtect
        if sec_names.iter().any(|s| s.starts_with(".vmp") || s == ".vmp0" || s == ".vmp1") {
            let vmp_str = "VMProtect v2.x - 3.x".to_string();
            protectors.push(vmp_str.clone());
            detections.push(DetectionItem {
                category: "Protector".to_string(),
                name: "VMProtect".to_string(),
                version: Some("2.x - 3.x".to_string()),
                details: "Protected with VMProtect code virtualization & anti-debug (.vmp sections found)".to_string(),
                confidence: 100,
            });
        }

        // 2. Themida / WinLicense
        if sec_names.iter().any(|s| s.starts_with(".themida") || s == ".winlice" || s == ".loadcon")
            || buffer_contains(buffer, b"This program is protected with Themida")
        {
            let themida_str = "Themida / WinLicense v2.x - 3.x".to_string();
            protectors.push(themida_str.clone());
            detections.push(DetectionItem {
                category: "Protector".to_string(),
                name: "Themida / WinLicense".to_string(),
                version: Some("2.x - 3.x".to_string()),
                details: "Protected with Oreans Themida virtualization & anti-dump".to_string(),
                confidence: 100,
            });
        }

        // 3. UPX
        if sec_names.iter().any(|s| s == "upx0" || s == "upx1" || s == ".upx0" || s == ".upx1") {
            let upx_str = "UPX Packer v3.x - 4.x".to_string();
            protectors.push(upx_str.clone());
            detections.push(DetectionItem {
                category: "Packer".to_string(),
                name: "UPX".to_string(),
                version: Some("3.x / 4.x".to_string()),
                details: "Compressed using UPX executable packer".to_string(),
                confidence: 95,
            });
        }

        // 4. Denuvo Anti-Tamper
        let has_denuvo_sec = sec_names.iter().any(|s| s == ".arch" || s == ".xtls" || s == ".mydata" || s == ".xcode");
        if has_denuvo_sec || buffer_contains(buffer, b"codefusion.technology") || buffer_contains(buffer, b"Denuvo") {
            let denuvo_str = "Denuvo Anti-Tamper (DRM)".to_string();
            protectors.push(denuvo_str.clone());
            detections.push(DetectionItem {
                category: "Protector".to_string(),
                name: "Denuvo Anti-Tamper".to_string(),
                version: None,
                details: "Denuvo Anti-Tamper DRM and protection sections detected".to_string(),
                confidence: 90,
            });
        }

        // 5. Blizzard Warden / Overwatch Loader
        if imported_dlls.iter().any(|d| d.to_lowercase().contains("overwatch_loader"))
            || buffer_contains(buffer, b"Overwatch_loader.dll")
            || sec_names.iter().any(|s| s == ".eid" || s == ".eidsig")
        {
            let bz_str = "Blizzard Overwatch Loader / Guard (Warden)".to_string();
            protectors.push(bz_str.clone());
            detections.push(DetectionItem {
                category: "Protector".to_string(),
                name: "Blizzard Protection Module".to_string(),
                version: Some("Overwatch 2".to_string()),
                details: "Encrypted .eid section and Overwatch_loader.dll dynamic dispatch protection".to_string(),
                confidence: 100,
            });
        }

        // 6. EasyAntiCheat (EAC)
        if buffer_contains(buffer, b"EasyAntiCheat") || imported_dlls.iter().any(|d| d.to_lowercase().contains("easyanticheat")) {
            let eac_str = "Easy Anti-Cheat (EAC)".to_string();
            protectors.push(eac_str.clone());
            detections.push(DetectionItem {
                category: "Anti-Cheat".to_string(),
                name: "Easy Anti-Cheat (EAC)".to_string(),
                version: None,
                details: "Integrated with Epic Games Easy Anti-Cheat module".to_string(),
                confidence: 95,
            });
        }

        // 7. BattlEye
        if sec_names.iter().any(|s| s.starts_with(".be"))
            || buffer_contains(buffer, b"battleye.com")
            || imported_dlls.iter().any(|d| d.to_lowercase().contains("beclient"))
        {
            let be_str = "BattlEye".to_string();
            protectors.push(be_str.clone());
            detections.push(DetectionItem {
                category: "Anti-Cheat".to_string(),
                name: "BattlEye".to_string(),
                version: None,
                details: "Integrated with BattlEye anticheat system".to_string(),
                confidence: 95,
            });
        }

        // 8. Languages & Compilers Heuristics
        if sec_names.iter().any(|s| s == ".rustc")
            || buffer_contains(buffer, b"rust_panic")
            || buffer_contains(buffer, b"/rustc/")
            || buffer_contains(buffer, b"core::panicking")
        {
            *compiler = Some("Rust (rustc)".to_string());
            *possible_language = "Rust".to_string();
            detections.push(DetectionItem {
                category: "Compiler".to_string(),
                name: "Rust".to_string(),
                version: None,
                details: "Compiled with Rust language runtime".to_string(),
                confidence: 100,
            });
        } else if buffer_contains(buffer, b"Go build ID")
            || buffer_contains(buffer, b"runtime.goexit")
            || buffer_contains(buffer, b"runtime.morestack")
        {
            *compiler = Some("Go (gc)".to_string());
            *possible_language = "Golang".to_string();
            detections.push(DetectionItem {
                category: "Compiler".to_string(),
                name: "Golang".to_string(),
                version: None,
                details: "Compiled with Go runtime".to_string(),
                confidence: 100,
            });
        } else if buffer_contains(buffer, b"_MEIPASS")
            || buffer_contains(buffer, b"pyi-runtime-tmpdir")
            || buffer_contains(buffer, b"python3.dll")
            || buffer_contains(buffer, b"NUITKA_ONEFILE")
            || imported_dlls.iter().any(|d| d.to_lowercase().starts_with("python"))
        {
            *compiler = Some("Python (PyInstaller / Nuitka / Embedded)".to_string());
            *possible_language = "Python".to_string();
            detections.push(DetectionItem {
                category: "Language".to_string(),
                name: "Python (Packer/Embedded)".to_string(),
                version: None,
                details: "Python standalone bundle or embedded interpreter detected".to_string(),
                confidence: 95,
            });
        } else if buffer_contains(buffer, b"Borland") || buffer_contains(buffer, b"Delphi") || buffer_contains(buffer, b"FastMM") {
            *compiler = Some("Embarcadero Delphi / C++Builder".to_string());
            *possible_language = "Delphi / Pascal".to_string();
            detections.push(DetectionItem {
                category: "Compiler".to_string(),
                name: "Delphi".to_string(),
                version: None,
                details: "Embarcadero / Borland Delphi Pascal runtime".to_string(),
                confidence: 90,
            });
        } else if imported_dlls.iter().any(|d| d.to_lowercase().contains("node.dll") || d.to_lowercase().contains("electron"))
            || buffer_contains(buffer, b"electron.asar")
        {
            *compiler = Some("Electron / Node.js Runtime".to_string());
            *possible_language = "JavaScript / TypeScript (Electron)".to_string();
            detections.push(DetectionItem {
                category: "Language".to_string(),
                name: "Electron / Node.js".to_string(),
                version: None,
                details: "Chromium & Node.js desktop framework runtime".to_string(),
                confidence: 95,
            });
        } else if imported_dlls.iter().any(|d| d.to_lowercase() == "msvbvm60.dll" || d.to_lowercase() == "msvbvm50.dll") {
            *compiler = Some("Microsoft Visual Basic 5.0/6.0".to_string());
            *possible_language = "Visual Basic 6".to_string();
        } else if buffer_contains(buffer, b"MSVC") || buffer_contains(buffer, b"Microsoft Visual C++") || sec_names.iter().any(|s| s == ".rdata") {
            *compiler = Some("Microsoft Visual C/C++".to_string());
            *linker = Some("Microsoft Linker".to_string());
            *possible_language = "C / C++".to_string();
        } else if buffer_contains(buffer, b"GCC: (") || buffer_contains(buffer, b"MinGW") {
            *compiler = Some("GNU GCC / MinGW".to_string());
            *possible_language = "C / C++ (GCC)".to_string();
        }
    }

    fn build_raw_analysis(
        path: &Path,
        filename: String,
        relative_path: String,
        size_bytes: u64,
        sha256: String,
        buffer: &[u8],
    ) -> Result<FileAnalysis, String> {
        let entropy = calculate_entropy(buffer);
        let crypto_constants = detect_crypto_constants(buffer);

        let ext_lang = path.extension()
            .and_then(|e| e.to_str())
            .and_then(crate::engine::language::LanguageRegistry::from_extension);

        let is_sys = filename.to_lowercase().ends_with(".sys");
        let is_dll = filename.to_lowercase().ends_with(".dll");
        let is_exe = filename.to_lowercase().ends_with(".exe");

        let format = if is_sys {
            "Driver (SYS)".to_string()
        } else if is_dll {
            "DLL (Protected / Custom)".to_string()
        } else if is_exe {
            "PE32+ (Protected EXE)".to_string()
        } else if let Some(lang) = ext_lang {
            format!("{} Source / Asset", lang)
        } else {
            "Raw Binary / Asset".to_string()
        };

        let base_language = ext_lang.unwrap_or("Unknown").to_string();

        let possible_language = if is_exe || is_dll || is_sys {
            if base_language == "Unknown" {
                "C / C++ (Compiled)".to_string()
            } else {
                base_language
            }
        } else {
            base_language
        };

        Ok(FileAnalysis {
            path: path.to_string_lossy().to_string(),
            filename,
            relative_path,
            size_bytes,
            sha256,
            format,
            architecture: if is_exe || is_dll || is_sys { "x86_64".to_string() } else { "Unknown".to_string() },
            is_64bit: is_exe || is_dll || is_sys,
            is_dotnet: false,
            is_driver: is_sys,
            is_signed: false,
            subsystem: if is_exe { "Windows GUI / Console".to_string() } else if is_sys { "Native Driver".to_string() } else { "Unknown".to_string() },
            entry_point: 0,
            overall_entropy: (entropy * 100.0).round() / 100.0,
            compiler: None,
            linker: None,
            possible_language,
            protectors: Vec::new(),
            detections: Vec::new(),
            sections: Vec::new(),
            imports_count: 0,
            imported_dlls: Vec::new(),
            exports_count: 0,
            suspicious_imports: Vec::new(),
            crypto_constants,
        })
    }
}

fn buffer_contains(buffer: &[u8], pattern: &[u8]) -> bool {
    if pattern.is_empty() || buffer.len() < pattern.len() {
        return false;
    }
    buffer.windows(pattern.len()).any(|w| w == pattern)
}
