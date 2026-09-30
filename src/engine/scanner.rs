use crate::engine::anticheat::analyze_anticheats;
use crate::engine::engine_detector::detect_engine;
use crate::engine::pe::PeAnalyzer;
use crate::models::report::{FileAnalysis, ScanReport, ScanSummaryStats};
use chrono::Local;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use walkdir::WalkDir;

pub struct Scanner;

impl Scanner {
    pub fn scan_target(target: &Path) -> Result<ScanReport, String> {
        let start_time = Instant::now();
        let target_buf = target.to_path_buf();

        let (all_files, is_single_file) = if target.is_file() {
            (vec![target_buf.clone()], true)
        } else {
            let files: Vec<PathBuf> = WalkDir::new(target)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| e.path().to_path_buf())
                .collect();
            (files, false)
        };

        let total_files_scanned = all_files.len();

        // Filter files to prioritize PE binaries, DLLs, SYS drivers, scripts, and key configs
        let mut binary_paths = Vec::new();
        let mut sample_strings = Vec::new();

        for p in &all_files {
            let ext = p.extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Binaries to thoroughly analyze with PE parser
            if ext == "exe" || ext == "dll" || ext == "sys" || ext == "ocx" || ext == "bin" || ext == "xem" {
                binary_paths.push(p.clone());
            }

            // Extract small string snippet from up to 50 files for anticheat / engine signatures
            if sample_strings.len() < 200 {
                if let Ok(mut f) = File::open(p) {
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = f.read(&mut buf) {
                        let text = String::from_utf8_lossy(&buf[..n]);
                        for line in text.lines().take(5) {
                            if line.len() > 4 {
                                sample_strings.push(line.to_string());
                            }
                        }
                    }
                }
            }
        }

        // If no binaries found (e.g. single raw file analyzed), include target itself
        if binary_paths.is_empty() && is_single_file {
            binary_paths.push(target_buf.clone());
        }

        let root_dir = if is_single_file {
            target.parent().unwrap_or(target)
        } else {
            target
        };

        // PARALLEL ANALYSIS of ALL files across ALL subfolders with Rayon
        let files_analysis: Vec<FileAnalysis> = all_files
            .par_iter()
            .filter_map(|path| PeAnalyzer::analyze(path, root_dir).ok())
            .collect();

        // Detect Anti-Cheat
        let path_refs: Vec<&Path> = all_files.iter().map(|p| p.as_path()).collect();
        let anticheats = analyze_anticheats(&path_refs, &sample_strings);

        // Detect Game Engine
        let game_engine = detect_engine(&path_refs, &sample_strings);

        // Target type heuristic
        let is_game = game_engine.is_some()
            || !anticheats.is_empty()
            || all_files.iter().any(|f| {
                let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
                name.contains("game") || name.ends_with(".pak") || name.ends_with(".vpk") || name.ends_with(".pck")
            });

        let target_type = if is_single_file {
            if files_analysis.iter().any(|f| f.is_driver) {
                "Kernel Driver / SYS".to_string()
            } else if files_analysis.iter().any(|f| f.format.contains("DLL")) {
                "Dynamic Library (DLL)".to_string()
            } else {
                "Single Executable".to_string()
            }
        } else if is_game {
            "Game Application / Suite".to_string()
        } else {
            "Software Application / Directory".to_string()
        };

        // Aggregate detections, compilers, languages, protections
        let mut protections_set = HashSet::new();
        let mut compilers_set = HashSet::new();
        let mut crypto_set = HashSet::new();
        let mut middlewares_set = HashSet::new();

        let mut total_executables = 0;
        let mut total_dlls = 0;
        let mut total_drivers = 0;
        let mut packed_count = 0;
        let mut high_entropy_count = 0;
        let mut entropy_sum = 0.0;
        let mut max_entropy = 0.0;

        for f in &files_analysis {
            let lower = f.filename.to_lowercase();
            if f.format.contains("EXE") || lower.ends_with(".exe") {
                total_executables += 1;
            } else if f.format.contains("DLL") || lower.ends_with(".dll") {
                total_dlls += 1;
            } else if f.is_driver || lower.ends_with(".sys") {
                total_drivers += 1;
            }

            if f.overall_entropy >= 7.2 {
                high_entropy_count += 1;
            }
            if f.overall_entropy > max_entropy {
                max_entropy = f.overall_entropy;
            }
            entropy_sum += f.overall_entropy;

            for det in &f.detections {
                match det.category.as_str() {
                    "Protector" => {
                        protections_set.insert(det.name.clone());
                    }
                    "Packer" => {
                        packed_count += 1;
                        protections_set.insert(format!("Packer: {}", det.name));
                    }
                    "Compiler" => {
                        compilers_set.insert(det.name.clone());
                    }
                    "Crypto" => {
                        crypto_set.insert(det.name.clone());
                    }
                    _ => {}
                }
            }

            // Check imported middlewares
            for dll in &f.imported_dlls {
                let d = dll.to_lowercase();
                if d.starts_with("d3d") || d.starts_with("dxgi") {
                    middlewares_set.insert("DirectX".to_string());
                } else if d.contains("vulkan") {
                    middlewares_set.insert("Vulkan".to_string());
                } else if d.contains("opengl") {
                    middlewares_set.insert("OpenGL".to_string());
                } else if d.contains("fmod") {
                    middlewares_set.insert("FMOD Audio".to_string());
                } else if d.contains("wwise") || d.contains("ak sound") {
                    middlewares_set.insert("Audiokinetic Wwise".to_string());
                } else if d.contains("bink") {
                    middlewares_set.insert("Bink Video".to_string());
                } else if d.contains("physx") {
                    middlewares_set.insert("NVIDIA PhysX".to_string());
                }
            }
        }

        for ac in &anticheats {
            protections_set.insert(format!("Anti-Cheat: {}", ac.name));
        }

        let avg_entropy = if !files_analysis.is_empty() {
            (entropy_sum / files_analysis.len() as f64 * 100.0).round() / 100.0
        } else {
            0.0
        };

        let summary_stats = ScanSummaryStats {
            total_executables,
            total_dlls,
            total_drivers,
            packed_count,
            high_entropy_count,
            average_entropy: avg_entropy,
            max_entropy: (max_entropy * 100.0).round() / 100.0,
        };

        let duration = start_time.elapsed().as_millis();

        let mut protectors_set = HashSet::new();
        let mut languages_set = HashSet::new();

        for f in &files_analysis {
            for prot in &f.protectors {
                protectors_set.insert(prot.clone());
            }
            if !f.possible_language.is_empty() && f.possible_language != "Unknown" {
                languages_set.insert(f.possible_language.clone());
            }
        }

        // Aggregate additional languages discovered across the entire folder (e.g. .lua, .js, .py, .hlsl, .rs)
        for ext_lang in crate::engine::language::LanguageRegistry::aggregate_from_files(&all_files) {
            languages_set.insert(ext_lang);
        }


        // App Name extraction (e.g. "Overwatch", "Delta Force", "Valorant")
        let app_name = if is_single_file {
            target.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Application")
                .to_string()
        } else {
            let mut folder_name = target.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();

            // If selected folder is a generic subfolder (e.g., Win64, Binaries), try parent directory
            let generic_folders = ["bin", "binaries", "win64", "x64", "win32", "shipping", "game", "client", "release", "debug"];
            if generic_folders.iter().any(|&g| folder_name.eq_ignore_ascii_case(g)) {
                if let Some(parent) = target.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) {
                    if !generic_folders.iter().any(|&g| parent.eq_ignore_ascii_case(g)) {
                        folder_name = parent.to_string();
                    }
                }
            }

            // Filter strictly to true .exe files
            let exe_candidates: Vec<&FileAnalysis> = files_analysis.iter().filter(|f| {
                f.filename.to_lowercase().ends_with(".exe")
            }).collect();

            // 1. Check if there's an executable matching the folder name (e.g. Overwatch.exe in D:\Overwatch)
            let exact_match = exe_candidates.iter().find(|f| {
                let stem = f.filename.trim_end_matches(".exe").trim_end_matches(".EXE");
                stem.eq_ignore_ascii_case(&folder_name)
            });

            // 2. Main game shipping or client executable (e.g. DeltaForceClient-Win64-Shipping.exe)
            let main_shipping_exe = exe_candidates.iter().find(|f| {
                let name = f.filename.to_lowercase();
                name.contains("shipping") || name.contains("game") || name.contains("client")
            });

            // 3. Any non-launcher / non-updater / non-crash executable
            let primary_exe = exe_candidates.iter().find(|f| {
                let name = f.filename.to_lowercase();
                !name.contains("crash") && !name.contains("error") && !name.contains("browser") 
                    && !name.contains("launcher") && !name.contains("helper") && !name.contains("update")
                    && !name.contains("setup") && !name.contains("install") && !name.contains("report")
            });

            if !folder_name.is_empty() && !generic_folders.iter().any(|&g| folder_name.eq_ignore_ascii_case(g)) {
                folder_name
            } else if let Some(exe) = exact_match.or(main_shipping_exe).or(primary_exe).or(exe_candidates.first()) {
                let stem = exe.filename.trim_end_matches(".exe").trim_end_matches(".EXE");
                stem.replace("-Win64-Shipping", "")
                    .replace("-Shipping", "")
                    .replace("_Shipping", "")
            } else if !folder_name.is_empty() {
                folder_name
            } else {
                "Application".to_string()
            }
        };

        let binary_files_analyzed = files_analysis.iter().filter(|f| {
            let lower = f.filename.to_lowercase();
            f.format.contains("EXE") || f.format.contains("DLL") || f.is_driver 
                || lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys")
        }).count();

        Ok(ScanReport {
            app_name,
            target_path: target.to_string_lossy().to_string(),
            target_type,
            scan_time: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            scan_duration_ms: duration,
            total_files_scanned,
            binary_files_analyzed,
            game_engine,
            anticheats,
            protectors_detected: protectors_set.into_iter().collect(),
            protections_found: protections_set.into_iter().collect(),
            compilers_detected: compilers_set.into_iter().collect(),
            languages_detected: languages_set.into_iter().collect(),
            middlewares_detected: middlewares_set.into_iter().collect(),
            crypto_algorithms: crypto_set.into_iter().collect(),
            files: files_analysis,
            summary_stats,
        })
    }
}

