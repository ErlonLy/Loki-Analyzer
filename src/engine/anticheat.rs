use crate::models::report::AntiCheatSummary;
use std::collections::HashSet;
use std::path::Path;

pub struct KnownAntiCheat {
    pub name: &'static str,
    pub vendor: &'static str,
    pub protection_type: &'static str,
    pub default_driver: &'static str,
    pub default_service: &'static str,
    pub file_indicators: &'static [&'static str],
    pub string_indicators: &'static [&'static str],
}

pub const KNOWN_ANTICHEATS: &[KnownAntiCheat] = &[
    KnownAntiCheat {
        name: "Riot Vanguard",
        vendor: "Riot Games",
        protection_type: "Kernel-Level (Ring 0 Boot-Start Driver)",
        default_driver: "vgk.sys",
        default_service: "vgc",
        file_indicators: &["vgk.sys", "vgc.exe", "vgame.exe", "vanguard"],
        string_indicators: &["riot vanguard", "vgk.sys", "vgc.exe", "riot games, inc."],
    },
    KnownAntiCheat {
        name: "ACE (Anti-Cheat Expert)",
        vendor: "Tencent Games",
        protection_type: "Kernel-Level (Ring 0 Driver)",
        default_driver: "ACE-GAME.sys",
        default_service: "AntiCheatExpert",
        file_indicators: &[
            "anticheatexpert",
            "ace-game.sys",
            "ace-game",
            "ace_game.sys",
            "ace-base.dll",
            "ace-safe.dll",
            "ace-loader.exe",
            "ace-tray.exe",
            "ace-ipc.dll",
            "sguard64.exe",
            "sguard32.exe",
            "sguard.dll",
            "sguard64.sys",
            "sguard.sys",
        ],
        string_indicators: &[
            "anticheatexpert",
            "tencent ace",
            "sguard",
            "ace-base.dll",
            "ace-game.sys",
            "anti-cheat expert",
        ],
    },
    KnownAntiCheat {
        name: "EA AntiCheat (EAAC)",
        vendor: "Electronic Arts",
        protection_type: "Kernel-Level (Ring 0 Driver)",
        default_driver: "EAAntiCheat.sys",
        default_service: "EAAntiCheatService",
        file_indicators: &[
            "eaanticheat",
            "eaanticheat.sys",
            "eaanticheat.gameservice.exe",
            "eaanticheat.gameservice.dll",
        ],
        string_indicators: &["eaanticheat", "electronic arts anticheat", "ea anticheat"],
    },
    KnownAntiCheat {
        name: "Activision Ricochet",
        vendor: "Activision",
        protection_type: "Kernel-Level (Ring 0 Driver)",
        default_driver: "randgrid.sys",
        default_service: "randgrid",
        file_indicators: &["randgrid.sys", "ricochet", "randgrid"],
        string_indicators: &["ricochet", "randgrid.sys", "call of duty anticheat"],
    },
    KnownAntiCheat {
        name: "Easy Anti-Cheat (EAC)",
        vendor: "Epic Games / Kamu",
        protection_type: "Kernel-Level (Ring 0 Driver) + User-Mode Hooking",
        default_driver: "EasyAntiCheat.sys",
        default_service: "EasyAntiCheat",
        file_indicators: &[
            "easyanticheat",
            "easyanticheat.sys",
            "easyanticheat_x64.dll",
            "easyanticheat_x86.dll",
            "easyanticheat_setup.exe",
            "eac_server.dll",
            "easyanticheat_eos.sys",
            "easyanticheat_eos_setup.exe",
        ],
        string_indicators: &[
            "easyanticheat",
            "easy anti-cheat",
            "kamu auto-update",
            "easyanticheat.sys",
        ],
    },
    KnownAntiCheat {
        name: "BattlEye",
        vendor: "BattlEye Innovations",
        protection_type: "Kernel-Level (Ring 0 Driver) + VMProtect",
        default_driver: "BEDaisy.sys",
        default_service: "BEService",
        file_indicators: &[
            "bedaisy.sys",
            "beservice.exe",
            "beservice_x64.exe",
            "beclient.dll",
            "beclient_x64.dll",
            "battleye",
        ],
        string_indicators: &[
            "battleye",
            "bedaisy.sys",
            "beservice",
            "battleye innovations",
        ],
    },
    KnownAntiCheat {
        name: "Denuvo Anti-Cheat (DAC)",
        vendor: "Irdeto",
        protection_type: "Kernel-Level (Ring 0 Driver)",
        default_driver: "denuvo-anti-cheat.sys",
        default_service: "DenuvoAntiCheat",
        file_indicators: &[
            "denuvo-anti-cheat",
            "denuvo-anti-cheat.sys",
            "denuvo-anti-cheat-update.exe",
        ],
        string_indicators: &["denuvo anti-cheat", "irdeto denuvo"],
    },
    KnownAntiCheat {
        name: "Denuvo Anti-Tamper (DRM)",
        vendor: "Irdeto",
        protection_type: "User-Mode Binary Obfuscation / Virtualization",
        default_driver: "None (DRM)",
        default_service: "None",
        file_indicators: &[".xtls", ".arch"],
        string_indicators: &[
            "denuvo",
            "dnuv",
            "https://support.codefusion.technology",
        ],
    },
    KnownAntiCheat {
        name: "XIGNCODE3",
        vendor: "Wellbia",
        protection_type: "Kernel-Level Driver + Encrypted Container",
        default_driver: "xhunter1.sys",
        default_service: "xigncode",
        file_indicators: &[
            "x3.xem",
            "xigncode.xem",
            "xigncode3",
            "xhunter1.sys",
            "xinaudio.xem",
        ],
        string_indicators: &["wellbia", "xigncode", "x3.xem", "xhunter1.sys"],
    },
    KnownAntiCheat {
        name: "Valve Anti-Cheat (VAC)",
        vendor: "Valve Corporation",
        protection_type: "User-Mode Memory Scanner & Steam Client Module",
        default_driver: "None",
        default_service: "SteamService",
        file_indicators: &["steamservice.dll", "steamclient.dll", "steamclient64.dll"],
        string_indicators: &["valve anti-cheat", "vac module", "steamservice.dll"],
    },
    KnownAntiCheat {
        name: "miHoYo / HoYoverse Anti-Cheat (mhyprot)",
        vendor: "miHoYo / Cognosphere",
        protection_type: "Kernel-Level (Ring 0 Driver)",
        default_driver: "mhyprot2.sys",
        default_service: "mhyprot2",
        file_indicators: &[
            "mhyprot2.sys",
            "mhyprot3.sys",
            "hoyoverse",
            "mihoyoprotect",
            "hopprot.sys",
        ],
        string_indicators: &["mhyprot", "mihoyo", "cognosphere"],
    },
    KnownAntiCheat {
        name: "Equ8 Anti-Cheat",
        vendor: "intugame",
        protection_type: "Kernel-Level Driver",
        default_driver: "equ8_helper.sys",
        default_service: "equ8",
        file_indicators: &["equ8", "equ8_helper.sys", "anticheat_equ8.dll"],
        string_indicators: &["equ8", "intugame"],
    },
    KnownAntiCheat {
        name: "GKP (Game Protect)",
        vendor: "Nexon",
        protection_type: "User-Mode & Kernel Guard",
        default_driver: "BlackCall.sys",
        default_service: "BlackCipher",
        file_indicators: &["blackcipher", "blackcall.sys", "ngclient.aes", "blackxchg.aes"],
        string_indicators: &["blackcipher", "nexon security", "blackcall.sys"],
    },
];

/// Scan a set of discovered file names and binary strings to identify active Anti-Cheats and their versions
pub fn analyze_anticheats(files: &[&Path], all_strings: &[String]) -> Vec<AntiCheatSummary> {
    let mut summaries = Vec::new();
    let mut detected_names = HashSet::new();

    let file_entries: Vec<(String, String)> = files
        .iter()
        .map(|p| {
            let fname = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
            let fpath = p.to_string_lossy().to_lowercase().replace('\\', "/");
            (fname, fpath)
        })
        .collect();

    for ac in KNOWN_ANTICHEATS {
        let mut evidence = Vec::new();
        let mut driver_found = None;

        // 1. Check file and directory path indicators
        for &indicator in ac.file_indicators {
            for (fname, fpath) in &file_entries {
                if fname.contains(indicator) || fpath.contains(indicator) {
                    evidence.push(format!("File indicator matched: '{}'", fname));
                    if fname.ends_with(".sys") {
                        driver_found = Some(fname.clone());
                    }
                }
            }
        }

        // 2. Check binary string indicators
        for &s_ind in ac.string_indicators {
            for s in all_strings {
                if s.to_lowercase().contains(s_ind) {
                    evidence.push(format!("Binary string signature found: '{}'", s_ind));
                    break;
                }
            }
        }

        if !evidence.is_empty() && detected_names.insert(ac.name) {
            // Version detection heuristic
            let mut detected_version = None;
            for ev in &evidence {
                // Look for patterns like v1.2.3 or 2024.x
                if let Some(pos) = ev.find("version ") {
                    let rest = &ev[pos + 8..];
                    if let Some(end) = rest.find(' ') {
                        detected_version = Some(rest[..end].to_string());
                    }
                }
            }

            summaries.push(AntiCheatSummary {
                detected: true,
                name: ac.name.to_string(),
                vendor: ac.vendor.to_string(),
                version: detected_version,
                driver_file: driver_found.or_else(|| {
                    if ac.default_driver != "None" {
                        Some(ac.default_driver.to_string())
                    } else {
                        None
                    }
                }),
                service_name: if ac.default_service != "None" {
                    Some(ac.default_service.to_string())
                } else {
                    None
                },
                protection_type: ac.protection_type.to_string(),
                evidence,
            });
        }
    }

    summaries
}
