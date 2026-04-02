use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::app::App;
use crate::scanners::Severity;

#[derive(Serialize)]
struct ExportReport {
    scan_id: String,
    target: String,
    generated_at: String,
    results: Vec<ExportScanResult>,
}

#[derive(Serialize)]
struct ExportScanResult {
    scanner: String,
    target: String,
    started_at: String,
    finished_at: String,
    success: bool,
    error: Option<String>,
    findings: Vec<ExportFinding>,
    raw_output: String,
}

#[derive(Serialize)]
struct ExportFinding {
    title: String,
    severity: String,
    description: String,
    details: String,
}

pub fn export_results(app: &App, path: &str) -> Result<()> {
    let extension = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("json");

    match extension {
        "json" => export_json(app, path),
        "txt" => export_txt(app, path),
        _ => export_json(app, path),
    }
}

fn export_json(app: &App, path: &str) -> Result<()> {
    let report = build_report(app);
    let json = serde_json::to_string_pretty(&report).context("Failed to serialize report")?;
    fs::write(path, json).context(format!("Failed to write to {}", path))?;
    Ok(())
}

fn export_txt(app: &App, path: &str) -> Result<()> {
    let mut output = String::new();

    output.push_str("═══════════════════════════════════════════════════════\n");
    output.push_str("  OctoScan Security Audit Report\n");
    output.push_str("═══════════════════════════════════════════════════════\n\n");
    output.push_str(&format!("Scan ID:    {}\n", app.id));
    output.push_str(&format!("Target:     {}\n", app.target));
    output.push_str(&format!("Generated:  {}\n", Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    output.push_str(&format!("Scanners:   {}\n\n", app.selected_scanners.iter().map(|s| s.to_string()).collect::<Vec<_>>().join(", ")));

    for result in &app.results {
        output.push_str("───────────────────────────────────────────────────────\n");
        output.push_str(&format!("  Scanner: {}\n", result.scanner));
        output.push_str(&format!("  Status:  {}\n", if result.success { "Success" } else { "Error" }));

        let duration = result.finished_at - result.started_at;
        output.push_str(&format!("  Duration: {}s\n", duration.num_seconds()));
        output.push_str(&format!("  Findings: {}\n", result.findings.len()));
        output.push_str("───────────────────────────────────────────────────────\n\n");

        if let Some(ref err) = result.error {
            output.push_str(&format!("  ERROR: {}\n\n", err));
        }

        for finding in &result.findings {
            let severity_tag = match finding.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::High => "[HIGH]    ",
                Severity::Medium => "[MEDIUM]  ",
                Severity::Low => "[LOW]     ",
                Severity::Info => "[INFO]    ",
            };

            output.push_str(&format!("  {} {}\n", severity_tag, finding.title));
            if !finding.description.is_empty() {
                output.push_str(&format!("           {}\n", finding.description));
            }
            if !finding.details.is_empty() {
                output.push_str(&format!("           {}\n", finding.details));
            }
            output.push('\n');
        }

        if result.findings.is_empty() && !result.raw_output.is_empty() {
            output.push_str("  Raw Output:\n");
            for line in result.raw_output.lines() {
                output.push_str(&format!("    {}\n", line));
            }
            output.push('\n');
        }
    }

    output.push_str("═══════════════════════════════════════════════════════\n");
    output.push_str("  End of Report\n");
    output.push_str("═══════════════════════════════════════════════════════\n");

    fs::write(path, output).context(format!("Failed to write to {}", path))?;
    Ok(())
}

fn build_report(app: &App) -> ExportReport {
    ExportReport {
        scan_id: app.id.to_string(),
        target: app.target.clone(),
        generated_at: Utc::now().to_rfc3339(),
        results: app
            .results
            .iter()
            .map(|r| ExportScanResult {
                scanner: r.scanner.to_string(),
                target: r.target.clone(),
                started_at: r.started_at.to_rfc3339(),
                finished_at: r.finished_at.to_rfc3339(),
                success: r.success,
                error: r.error.clone(),
                findings: r
                    .findings
                    .iter()
                    .map(|f| ExportFinding {
                        title: f.title.clone(),
                        severity: f.severity.to_string(),
                        description: f.description.clone(),
                        details: f.details.clone(),
                    })
                    .collect(),
                raw_output: r.raw_output.clone(),
            })
            .collect(),
    }
}
