use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("feroxbuster").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Feroxbuster,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("feroxbuster is not installed or not in PATH".to_string()),
        });
    }

    let output = Command::new("feroxbuster")
        .args([
            "-u",
            target,
            "--silent",
            "--no-state",
            "--auto-tune",
            "--json",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute feroxbuster")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Feroxbuster,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("feroxbuster exited with status: {}", output.status)),
        });
    }

    let findings = parse_feroxbuster_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Feroxbuster,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_feroxbuster_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            // feroxbuster JSON lines contain type, url, status, content_length, etc.
            let obj_type = json["type"].as_str().unwrap_or("");
            if obj_type != "response" {
                continue;
            }

            let url = json["url"].as_str().unwrap_or("unknown").to_string();
            let status = json["status"].as_u64().unwrap_or(0);
            let content_length = json["content_length"].as_u64().unwrap_or(0);
            let method = json["method"].as_str().unwrap_or("GET");

            let severity = match status {
                200 => Severity::Info,
                301 | 302 => Severity::Low,
                401 | 403 => Severity::Medium,
                500..=599 => Severity::High,
                _ => Severity::Info,
            };

            findings.push(Finding {
                title: format!("[{}] {} — {}", status, method, url),
                severity,
                description: format!("Status: {} | Size: {} bytes", status, content_length),
                details: url,
            });
        }
    }

    findings
}
