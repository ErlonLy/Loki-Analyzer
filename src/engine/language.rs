use std::collections::HashMap;

pub struct LanguageRegistry;

impl LanguageRegistry {
    /// Detect language by file extension
    pub fn from_extension(ext: &str) -> Option<&'static str> {
        let e = ext.to_lowercase();
        match e.as_str() {
            // Systems & Native
            "c" | "h" => Some("C"),
            "cpp" | "cxx" | "cc" | "c++" | "hpp" | "hxx" | "hh" | "h++" | "inl" | "ipp" => Some("C++"),
            "rs" | "rlib" => Some("Rust"),
            "go" => Some("Golang"),
            "asm" | "s" | "nasm" | "masm" | "inc" => Some("Assembly"),
            "d" | "di" => Some("D"),
            "zig" => Some("Zig"),
            "nim" => Some("Nim"),
            "pas" | "pp" | "dpr" | "dfm" => Some("Pascal / Delphi"),
            "f" | "f90" | "f95" | "for" => Some("Fortran"),
            "ada" | "adb" | "ads" => Some("Ada"),

            // Managed & JVM / .NET
            "cs" | "csx" => Some("C# (.NET)"),
            "vb" | "vbs" | "bas" => Some("Visual Basic (.NET)"),
            "fs" | "fsi" => Some("F#"),
            "java" | "class" | "jar" => Some("Java"),
            "kt" | "kts" => Some("Kotlin"),
            "scala" | "sc" => Some("Scala"),
            "clj" | "cljs" | "cljc" | "edn" => Some("Clojure"),
            "groovy" | "gvy" => Some("Groovy"),

            // Scripting, Web & Modern
            "js" | "mjs" | "cjs" => Some("JavaScript"),
            "ts" | "mts" | "cts" => Some("TypeScript"),
            "jsx" => Some("React JSX"),
            "tsx" => Some("React TSX"),
            "py" | "pyw" | "pyc" | "pyd" | "pyo" => Some("Python"),
            "lua" | "luac" | "luau" => Some("Lua"),
            "rb" | "erb" | "rake" => Some("Ruby"),
            "php" | "phtml" | "php3" | "php4" | "php5" => Some("PHP"),
            "pl" | "pm" | "t" => Some("Perl"),
            "r" | "rmd" => Some("R"),
            "swift" => Some("Swift"),
            "dart" => Some("Dart"),
            "v" => Some("Vlang"),
            "odin" => Some("Odin"),

            // Game Scripting, Shaders & Engines
            "hlsl" | "fx" | "fxh" => Some("HLSL Shader"),
            "glsl" | "vert" | "frag" | "comp" | "geom" | "tesc" | "tese" => Some("GLSL Shader"),
            "metal" => Some("Metal Shader"),
            "slang" => Some("Slang Shader"),
            "wgsl" => Some("WGSL WebGPU Shader"),
            "gd" => Some("GDScript (Godot)"),
            "gdshader" => Some("Godot Shader"),
            "gml" => Some("GML (GameMaker)"),
            "as" => Some("ActionScript / Flash"),
            "nut" => Some("Squirrel"),
            "uc" => Some("UnrealScript"),
            "verse" => Some("Verse (Unreal)"),
            "pawn" | "sma" => Some("PAWN (Source / AMX)"),

            // Web Markup & Styling
            "html" | "htm" | "xhtml" => Some("HTML"),
            "css" => Some("CSS"),
            "scss" | "sass" => Some("SCSS / Sass"),
            "less" => Some("Less"),
            "vue" => Some("Vue.js"),
            "svelte" => Some("Svelte"),

            // Config, Data & Schemas
            "json" | "json5" | "jsonc" => Some("JSON"),
            "yaml" | "yml" => Some("YAML"),
            "toml" => Some("TOML"),
            "xml" | "xsd" | "xsl" => Some("XML"),
            "ini" | "cfg" | "conf" => Some("Config / INI"),
            "proto" => Some("Protocol Buffers"),
            "graphql" | "gql" => Some("GraphQL"),
            "sql" => Some("SQL"),

            // Shell & System Scripts
            "bat" | "cmd" => Some("Windows Batch Script"),
            "ps1" | "psm1" | "psd1" => Some("PowerShell"),
            "sh" | "bash" | "zsh" => Some("Shell Script"),

            _ => None,
        }
    }

    /// Aggregate languages from a list of discovered file paths
    pub fn aggregate_from_files(files: &[std::path::PathBuf]) -> Vec<String> {
        let mut counts: HashMap<&'static str, usize> = HashMap::new();
        for p in files {
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if let Some(lang) = Self::from_extension(ext) {
                    *counts.entry(lang).or_insert(0) += 1;
                }
            }
        }
        let mut list: Vec<(&'static str, usize)> = counts.into_iter().collect();
        list.sort_by(|a, b| b.1.cmp(&a.1));
        list.into_iter().map(|(lang, _)| lang.to_string()).collect()
    }
}
