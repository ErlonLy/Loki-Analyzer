use crate::engine::scanner::Scanner;
use crate::export::html::HtmlExporter;
use rfd::FileDialog;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub struct GuiRunner;

impl GuiRunner {
    pub fn run() {
        Self::print_banner();

        loop {
            println!("\n  \x1b[1;33m[1]\x1b[0m 📁 Selecionar PASTA (Jogo ou Software)");
            println!("  \x1b[1;36m[2]\x1b[0m 📄 Selecionar ARQUIVO (.exe, .dll, .sys, driver)");
            println!("  \x1b[1;31m[3]\x1b[0m ❌ Sair\n");
            print!("  \x1b[1mEscolha uma opção (1-3):\x1b[0m ");
            io::stdout().flush().unwrap();

            let mut input = String::new();
            if io::stdin().read_line(&mut input).is_err() {
                continue;
            }

            match input.trim() {
                "1" => {
                    println!("\n\x1b[1;33m[+] Abrindo seletor de pasta...\x1b[0m");
                    if let Some(folder) = FileDialog::new().set_title("Loki Analyzer - Escolha a pasta do jogo").pick_folder() {
                        Self::execute_scan(&folder);
                    } else {
                        println!("\x1b[31m[-] Seleção cancelada.\x1b[0m");
                    }
                }
                "2" => {
                    println!("\n\x1b[1;36m[+] Abrindo seletor de arquivo...\x1b[0m");
                    if let Some(file) = FileDialog::new()
                        .set_title("Loki Analyzer - Escolha um executável ou driver")
                        .add_filter("Executáveis e Drivers", &["exe", "dll", "sys", "bin", "ocx"])
                        .add_filter("Todos os Arquivos", &["*"])
                        .pick_file()
                    {
                        Self::execute_scan(&file);
                    } else {
                        println!("\x1b[31m[-] Seleção cancelada.\x1b[0m");
                    }
                }
                "3" => {
                    println!("\n\x1b[1;32m[+] Finalizando Loki Analyzer. Até mais!\x1b[0m");
                    break;
                }
                _ => {
                    println!("\x1b[31m[-] Opção inválida. Digite 1, 2 ou 3.\x1b[0m");
                }
            }
        }
    }

    fn execute_scan(target: &Path) {
        println!("\n\x1b[1;32m====================================================\x1b[0m");
        println!("\x1b[1;33m[*] Iniciando varredura ultra-rápida em:\x1b[0m {}", target.display());
        println!("\x1b[1;32m====================================================\x1b[0m");

        match Scanner::scan_target(target) {
            Ok(report) => {
                println!("\x1b[1;32m[✓] Varredura concluída em {}ms!\x1b[0m", report.scan_duration_ms);
                println!("  • Alvo identificado como: \x1b[1;36m{}\x1b[0m", report.target_type);
                println!("  • Arquivos totais varridos: \x1b[1m{}\x1b[0m", report.total_files_scanned);
                println!("  • Binários dissecados (PE/DLL/SYS): \x1b[1m{}\x1b[0m", report.binary_files_analyzed);

                if let Some(ref engine) = report.game_engine {
                    println!("  • Engine Gráfica: \x1b[1;32m{}\x1b[0m", engine);
                }

                if !report.anticheats.is_empty() {
                    for ac in &report.anticheats {
                        println!("  • \x1b[1;31m[ALERTA DE ANTI-CHEAT]\x1b[0m \x1b[1m{}\x1b[0m ({})", ac.name, ac.protection_type);
                        if let Some(ref drv) = ac.driver_file {
                            println!("    └─ Driver associado: {}", drv);
                        }
                    }
                } else {
                    println!("  • Anti-Cheat: \x1b[37mNenhum de terceiros detectado\x1b[0m");
                }

                if !report.protections_found.is_empty() {
                    println!("  • Proteções / Packers: \x1b[1;35m{}\x1b[0m", report.protections_found.join(", "));
                }

                // Export HTML Dashboard
                let output_html = PathBuf::from("relatorio_loki.html");
                match HtmlExporter::export_dashboard(&report, &output_html) {
                    Ok(_) => {
                        println!("\n\x1b[1;32m[✓] Dashboard HTML gerado com sucesso:\x1b[0m {}", output_html.display());
                        println!("\x1b[1;33m[+] Abrindo relatório no navegador padrão...\x1b[0m");
                        let _ = webbrowser::open(output_html.to_str().unwrap_or("relatorio_loki.html"));
                    }
                    Err(e) => {
                        println!("\x1b[31m[-] Erro ao exportar HTML: {}\x1b[0m", e);
                    }
                }
            }
            Err(e) => {
                println!("\x1b[31m[-] Falha na análise: {}\x1b[0m", e);
            }
        }
    }

    fn print_banner() {
        println!("\x1b[1;33m");
        println!(r#"
  ██╗      ██████╗ ██╗  ██╗██╗     █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
  ██║     ██╔═══██╗██║ ██╔╝██║    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ██║     ██║   ██║█████╔╝ ██║    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██║     ██║   ██║██╔═██╗ ██║    ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ███████╗╚██████╔╝██║  ██╗██║    ██║  ██║██║ ╚████║██║  ██║███████╗██║    ███████╗███████╗██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝    ╚══════╝╚══════╝╚═╝  ╚═╝
        "#);
        println!("\x1b[1;36m  ════════════════════════════════════════════════════════════════════════════════════════════\x1b[0m");
        println!("\x1b[1;37m   Engine: \x1b[1;32mRust v2.0 (Rayon Multithreaded)\x1b[0m | \x1b[1;37mSignatures: \x1b[1;33mDiE (Detect-It-Easy) + AntiCheat Expert\x1b[0m");
        println!("\x1b[1;37m   Dashboard: \x1b[1;35mReact Tailwind Glassmorphism (Standalone HTML Export)\x1b[0m");
        println!("\x1b[1;36m  ════════════════════════════════════════════════════════════════════════════════════════════\x1b[0m");
    }
}
