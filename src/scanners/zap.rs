use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    // ZAP CLI can be `zap-cli` or `zap.sh` depending on installation
    let zap_cmd = if check_tool("zap-cli").await {
        "zap-cli"
    } else if check_tool("zaproxy").await {
        "zaproxy"
    } else {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Zap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("ZAP (zap-cli or zaproxy) is not installed or not in PATH".to_string()),
        });
    };

    // Use ZAP in command-line mode for a quick scan
    let output = Command::new(zap_cmd)
        .args(["quick-scan", "--self-contained", "-s", "xss,sqli", target])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute ZAP")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Zap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("ZAP exited with status: {}", output.status)),
        });
    }

    let findings = parse_zap_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Zap,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_zap_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try parsing as JSON first (ZAP API JSON output)
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(alerts) = json["alerts"].as_array() {
            for alert in alerts {
                let name = alert["name"].as_str().unwrap_or("Unknown").to_string();
                let risk_str = alert["risk"].as_str().unwrap_or("Informational");
                let severity = match risk_str {
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    "Low" => Severity::Low,
                    _ => Severity::Info,
                };
                let description = alert["description"].as_str().unwrap_or("").to_string();
                let solution = alert["solution"].as_str().unwrap_or("").to_string();

                findings.push(Finding {
                    title: name,
                    severity,
                    description,
                    details: format!("Solution: {}", solution),
                });
            }
        }
        return findings;
    }

    // Fallback: parse line-based output
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("WARN") || trimmed.starts_with("FAIL") {
            let severity = if trimmed.starts_with("FAIL") {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(Finding {
                title: trimmed.to_string(),
                severity,
                description: trimmed.to_string(),
                details: String::new(),
            });
        }
    }

    findings
}
