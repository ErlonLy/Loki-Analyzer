use crate::models::report::ScanReport;
use std::fs::File;
use std::io::Write;
use std::path::Path;

// Embed the pre-built singlefile React HTML dashboard
const DASHBOARD_TEMPLATE: &str = include_str!("../../frontend/dist/index.html");

pub struct HtmlExporter;

impl HtmlExporter {
    pub fn export_dashboard(report: &ScanReport, output_path: &Path) -> Result<(), String> {
        let json_data = serde_json::to_string(report)
            .map_err(|e| format!("Failed to serialize report to JSON: {}", e))?;

        // Inject window.__LOKI_REPORT__ before </head> or <body>
        let injection_script = format!(
            "<script>window.__LOKI_REPORT__ = {};</script>",
            json_data
        );

        let title_tag = format!("<title>{} - Loki Analyzer</title>", report.app_name);
        let mut final_html = if DASHBOARD_TEMPLATE.contains("<head>") {
            DASHBOARD_TEMPLATE.replace("<head>", &format!("<head>\n{}", injection_script))
        } else if DASHBOARD_TEMPLATE.contains("<body>") {
            DASHBOARD_TEMPLATE.replace("<body>", &format!("<body>\n{}", injection_script))
        } else {
            format!("{}\n{}", injection_script, DASHBOARD_TEMPLATE)
        };

        // Replace <title>...</title> with the analyzed app name
        if let Ok(re) = regex::Regex::new(r"<title>.*?</title>") {
            final_html = re.replace(&final_html, title_tag.as_str()).to_string();
        }

        let mut out_file = File::create(output_path)
            .map_err(|e| format!("Cannot create HTML file {}: {}", output_path.display(), e))?;

        out_file.write_all(final_html.as_bytes())
            .map_err(|e| format!("Failed to write HTML file: {}", e))?;

        Ok(())
    }
}
