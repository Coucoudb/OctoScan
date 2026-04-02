use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("nuclei").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Nuclei,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("nuclei is not installed or not in PATH".to_string()),
        });
    }

    let output = Command::new("nuclei")
        .args(["-u", target, "-jsonl", "-silent"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute nuclei")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Nuclei,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("nuclei exited with status: {}", output.status)),
        });
    }

    let findings = parse_nuclei_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Nuclei,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_nuclei_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let template_id = json["template-id"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();

            let name = json["info"]["name"]
                .as_str()
                .unwrap_or(&template_id)
                .to_string();

            let severity_str = json["info"]["severity"].as_str().unwrap_or("info");
            let severity = match severity_str.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };

            let description = json["info"]["description"]
                .as_str()
                .unwrap_or("")
                .to_string();

            let matched_at = json["matched-at"].as_str().unwrap_or("").to_string();

            findings.push(Finding {
                title: name,
                severity,
                description,
                details: format!("Template: {} | Matched: {}", template_id, matched_at),
            });
        }
    }

    findings
}
