use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("subfinder").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Subfinder,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("subfinder is not installed or not in PATH".to_string()),
        });
    }

    // Strip protocol for subfinder (it works with domains)
    let domain = target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target);

    let output = Command::new("subfinder")
        .args([
            "-d", domain, "-silent", "-all", // use all sources
            "-t", "50", // threads
            "-timeout", "30",  // timeout per source (seconds)
            "-nW", // remove wildcard subdomains
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute subfinder")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Subfinder,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("subfinder exited with status: {}", output.status)),
        });
    }

    let findings = parse_subfinder_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Subfinder,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_subfinder_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let subdomain = line.trim();
        if subdomain.is_empty() {
            continue;
        }

        findings.push(Finding {
            title: format!("Subdomain: {}", subdomain),
            severity: Severity::Info,
            description: format!("Discovered subdomain: {}", subdomain),
            details: subdomain.to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/subfinder/normal.txt");
        let findings = parse_subfinder_output(input);
        assert_eq!(findings.len(), 5);
        assert!(findings[0].title.contains("www.example.com"));
        assert!(findings[1].title.contains("mail.example.com"));
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn parse_empty_output() {
        let input = include_str!("../../tests/fixtures/subfinder/empty.txt");
        let findings = parse_subfinder_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_single_subdomain() {
        let input = include_str!("../../tests/fixtures/subfinder/single.txt");
        let findings = parse_subfinder_output(input);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("www.example.com"));
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_subfinder_output("");
        assert!(findings.is_empty());
    }
}
