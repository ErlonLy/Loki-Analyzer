use loki_analyzer::engine::scanner::Scanner;
use loki_analyzer::export::html::HtmlExporter;
use loki_analyzer::ui::runner::GuiRunner;
use std::env;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();

    // If an argument is provided (e.g. drag & drop or CLI path), scan immediately
    if args.len() > 1 {
        let target = PathBuf::from(&args[1]);
        if target.exists() {
            println!("[*] Alvo recebido via argumento: {}", target.display());
            match Scanner::scan_target(&target) {
                Ok(report) => {
                    let out_path = PathBuf::from("relatorio_loki.html");
                    if let Ok(_) = HtmlExporter::export_dashboard(&report, &out_path) {
                        println!("[✓] Relatório gerado com sucesso em: {}", out_path.display());
                        let _ = webbrowser::open(out_path.to_str().unwrap_or("relatorio_loki.html"));
                    }
                }
                Err(e) => eprintln!("[-] Erro: {}", e),
            }
            return;
        }
    }

    // Otherwise launch interactive runner
    GuiRunner::run();
}
