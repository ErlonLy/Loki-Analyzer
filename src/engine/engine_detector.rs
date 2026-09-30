use std::path::Path;

pub struct GameEngineSignature {
    pub name: &'static str,
    pub vendor: &'static str,
    pub files: &'static [&'static str],
    pub strings: &'static [&'static str],
}

pub const KNOWN_ENGINES: &[GameEngineSignature] = &[
    GameEngineSignature {
        name: "Blizzard Overwatch Engine",
        vendor: "Blizzard Entertainment",
        files: &["overwatch.exe", "overwatch_loader.dll", "blizzardbrowser"],
        strings: &["Overwatch", "TankEngine", "Blizzard Entertainment"],
    },
    GameEngineSignature {
        name: "Unreal Engine 5",
        vendor: "Epic Games",
        files: &[
            "engine/binaries",
            "unrealgame-win64-shipping",
            ".utoc",
            ".ucas",
            "ue5",
            "/engine/saved",
        ],
        strings: &["UnrealEngine5", "UE5", "FEngineLoop"],
    },
    GameEngineSignature {
        name: "Unreal Engine 4",
        vendor: "Epic Games",
        files: &[
            "ue4game",
            "ue4",
            "engine/binaries/thirdparty",
            "windowsnoeditor",
            "windowsclient",
            "/engine.ini",
            "engine.ini",
            "houdiniengine",
            "unrealpak",
        ],
        strings: &["UnrealEngine4", "UE4", "FEngineVersion"],
    },
    GameEngineSignature {
        name: "Unity (IL2CPP)",
        vendor: "Unity Technologies",
        files: &["gameassembly.dll", "unityplayer.dll", "globalgamemanagers", "il2cpp_data"],
        strings: &["GameAssembly.dll", "Unity Technologies", "il2cpp", "il2cpp_init"],
    },
    GameEngineSignature {
        name: "Unity (Mono)",
        vendor: "Unity Technologies",
        files: &["mono.dll", "monobdwgc-2.0.dll", "assembly-csharp.dll", "unityplayer.dll"],
        strings: &["UnityPlayer.dll", "Mono.dll", "UnityEngine"],
    },
    GameEngineSignature {
        name: "Godot Engine",
        vendor: "Godot Engine",
        files: &[".pck", "godot.exe"],
        strings: &["GodotEngine", "godot_engine", "Godot Engine"],
    },
    GameEngineSignature {
        name: "Source 2",
        vendor: "Valve",
        files: &["panorama", "client.dll", "engine2.dll"],
        strings: &["Source 2", "Valve Corporation", "engine2.dll"],
    },
    GameEngineSignature {
        name: "Source Engine",
        vendor: "Valve",
        files: &["hl2.exe", "tier0.dll", "vstdlib.dll", ".vpk"],
        strings: &["Valve Half-Life", "Valve Source", "tier0.dll"],
    },
    GameEngineSignature {
        name: "CryEngine",
        vendor: "Crytek",
        files: &["crysystem.dll", "cryrenderd3d11.dll", "cryengine"],
        strings: &["Crytek GmbH", "CryEngine", "CrySystem"],
    },
    GameEngineSignature {
        name: "Frostbite",
        vendor: "EA DICE",
        files: &["frostbite", "fbcl.dll"],
        strings: &["Frostbite", "EA Digital Illusions CE"],
    },
    GameEngineSignature {
        name: "id Tech",
        vendor: "id Software",
        files: &["idimage.dll", "idnet.dll", ".bimage"],
        strings: &["id Software", "idTech"],
    },
    GameEngineSignature {
        name: "RE Engine",
        vendor: "Capcom",
        files: &["re_chunk_000.pak", "re_chunk_", "via.reengine"],
        strings: &["CAPCOM CO., LTD.", "RE Engine", "via.reengine"],
    },
    GameEngineSignature {
        name: "GameMaker: Studio",
        vendor: "YoYo Games",
        files: &["data.win", "audiogroup1.dat"],
        strings: &["YoYo Games", "GameMaker:Studio", "GML"],
    },
    GameEngineSignature {
        name: "RPG Maker",
        vendor: "Gotcha Gotcha Games",
        files: &["rpg_rt.exe", "game.rgss3a", "package.json", "nw.exe"],
        strings: &["RPG Maker", "Enterbrain", "RPGVXAce"],
    },
    GameEngineSignature {
        name: "RedEngine",
        vendor: "CD PROJEKT RED",
        files: &[".bundle", ".archive", "red4ext.dll"],
        strings: &["CD PROJEKT S.A.", "REDengine", "Cyberpunk2077"],
    },
];

pub fn detect_engine(files: &[&Path], all_strings: &[String]) -> Option<String> {
    let lower_files: Vec<String> = files
        .iter()
        .filter_map(|p| p.to_str())
        .map(|s| s.to_lowercase().replace('\\', "/"))
        .collect();

    for eng in KNOWN_ENGINES {
        // Check files
        for &f_pattern in eng.files {
            if lower_files.iter().any(|f| f.contains(f_pattern)) {
                return Some(eng.name.to_string());
            }
        }
        // Check strings
        for &s_pattern in eng.strings {
            if all_strings.iter().any(|s| s.contains(s_pattern)) {
                return Some(eng.name.to_string());
            }
        }
    }

    // Heuristic fallback for custom Unreal Engine setups
    let has_engine_folder = lower_files.iter().any(|f| f.contains("/engine/") || f.contains("engine/saved") || f.contains("engine/content"));
    let has_binaries_or_paks = lower_files.iter().any(|f| f.contains("binaries/win64") || f.contains("windowsnoeditor") || f.ends_with(".pak"));
    if has_engine_folder && has_binaries_or_paks {
        if lower_files.iter().any(|f| f.contains(".utoc") || f.contains(".ucas")) {
            return Some("Unreal Engine 5".to_string());
        } else {
            return Some("Unreal Engine 4".to_string());
        }
    }

    None
}
