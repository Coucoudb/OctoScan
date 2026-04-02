use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("nmap").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Nmap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("nmap is not installed or not in PATH".to_string()),
        });
    }

    // Strip protocol for nmap (it works with hosts/IPs)
    let host = target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(target);

    let output = Command::new("nmap")
        .args(["-sV", "-sC", "--top-ports", "1000", "-T4", host])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute nmap")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Ok(ScanResult {
            scanner: ScannerType::Nmap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("nmap exited with status: {}", output.status)),
        });
    }

    let findings = parse_nmap_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Nmap,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_nmap_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Parse open ports: "80/tcp open http Apache httpd 2.4.41"
        if trimmed.contains("/tcp") && trimmed.contains("open") {
            let parts: Vec<&str> = trimmed.splitn(4, char::is_whitespace).collect();
            let port = parts.first().unwrap_or(&"unknown");
            let service_info = if parts.len() >= 4 {
                parts[3..].join(" ")
            } else {
                "unknown service".to_string()
            };

            findings.push(Finding {
                title: format!("Open port: {}", port),
                severity: Severity::Info,
                description: format!("Port {} is open", port),
                details: service_info,
            });
        }

        // Detect potential vulnerabilities from NSE scripts
        if trimmed.starts_with('|') && trimmed.contains("VULNERABLE") {
            findings.push(Finding {
                title: "NSE Vulnerability Detected".to_string(),
                severity: Severity::High,
                description: trimmed.to_string(),
                details: trimmed.to_string(),
            });
        }
    }

    findings
}
