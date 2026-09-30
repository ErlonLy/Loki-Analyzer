use loki_analyzer::engine::scanner::Scanner;
use loki_analyzer::export::html::HtmlExporter;
use loki_analyzer::models::report::ScanReport;
use std::path::PathBuf;
use tauri::Emitter;

#[derive(Clone, serde::Serialize)]
struct ScanProgressPayload {
    stage: String,
    percent: u32,
    message: String,
}

#[tauri::command]
async fn pick_folder() -> Result<Option<String>, String> {
    let folder = rfd::AsyncFileDialog::new()
        .set_title("Selecione a Pasta do Jogo ou Aplicativo")
        .pick_folder()
        .await;
    Ok(folder.map(|f| f.path().to_string_lossy().to_string()))
}

#[tauri::command]
async fn pick_file() -> Result<Option<String>, String> {
    let file = rfd::AsyncFileDialog::new()
        .set_title("Selecione o Executável, DLL ou Driver")
        .add_filter("Executáveis e Binários (*.exe, *.dll, *.sys)", &["exe", "dll", "sys", "ocx", "bin"])
        .add_filter("Scripts e Fontes (*.js, *.rs, *.cpp, *.py, *.lua)", &["js", "rs", "cpp", "py", "lua", "cs", "go"])
        .add_filter("Todos os Arquivos (*.*)", &["*"])
        .pick_file()
        .await;
    Ok(file.map(|f| f.path().to_string_lossy().to_string()))
}

#[tauri::command]
async fn run_scan(app: tauri::AppHandle, path: String) -> Result<ScanReport, String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("Caminho não encontrado: {}", path));
    }

    let _ = app.emit("scan_progress", ScanProgressPayload {
        stage: "indexing".into(),
        percent: 20,
        message: "Indexando diretórios e mapeando binários...".into(),
    });

    let app_handle = app.clone();
    let res = tokio::task::spawn_blocking(move || {
        let _ = app_handle.emit("scan_progress", ScanProgressPayload {
            stage: "heuristics".into(),
            percent: 50,
            message: "Detectando assinaturas de Anti-Cheats e Engines...".into(),
        });

        let scan_res = Scanner::scan_target(&p);

        let _ = app_handle.emit("scan_progress", ScanProgressPayload {
            stage: "sections".into(),
            percent: 90,
            message: "Processando entropia de seções e constantes criptográficas...".into(),
        });

        scan_res
    })
    .await
    .map_err(|e| format!("Falha na execução: {}", e))??;

    let _ = app.emit("scan_progress", ScanProgressPayload {
        stage: "done".into(),
        percent: 100,
        message: "Análise concluída com sucesso!".into(),
    });

    Ok(res)
}

#[tauri::command]
async fn open_report_in_browser(report: ScanReport) -> Result<String, String> {
    let out_path = PathBuf::from("relatorio_loki.html");
    HtmlExporter::export_dashboard(&report, &out_path)?;
    let full_path = std::fs::canonicalize(&out_path)
        .unwrap_or(out_path.clone());
    let _ = webbrowser::open(out_path.to_str().unwrap_or("relatorio_loki.html"));
    Ok(full_path.to_string_lossy().to_string())
}

#[tauri::command]
async fn save_report_html_dialog(report: ScanReport) -> Result<Option<String>, String> {
    let clean_name = report.app_name.to_lowercase().replace(' ', "_");
    let default_name = format!("relatorio_{}.html", clean_name);
    let dialog = rfd::AsyncFileDialog::new()
        .set_title("Salvar Relatório HTML")
        .set_file_name(&default_name)
        .add_filter("Arquivo HTML (*.html)", &["html"])
        .save_file()
        .await;

    if let Some(file_handle) = dialog {
        let path = file_handle.path();
        HtmlExporter::export_dashboard(&report, path)?;
        Ok(Some(path.to_string_lossy().to_string()))
    } else {
        Ok(None)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::default().build())
        .invoke_handler(tauri::generate_handler![
            pick_folder,
            pick_file,
            run_scan,
            open_report_in_browser,
            save_report_html_dialog
        ])
        .run(tauri::generate_context!())
        .expect("error while building tauri application");
}
