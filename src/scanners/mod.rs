pub mod feroxbuster;
pub mod httpx;
pub mod hydra;
pub mod nmap;
pub mod nuclei;
pub mod sqlmap;
pub mod subfinder;
pub mod wpscan;
pub mod zap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScannerType {
    Nmap,
    Nuclei,
    Zap,
    Feroxbuster,
    Sqlmap,
    Subfinder,
    Httpx,
    Wpscan,
    Hydra,
}

impl std::fmt::Display for ScannerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerType::Nmap => write!(f, "Nmap"),
            ScannerType::Nuclei => write!(f, "Nuclei"),
            ScannerType::Zap => write!(f, "ZAP"),
            ScannerType::Feroxbuster => write!(f, "Feroxbuster"),
            ScannerType::Sqlmap => write!(f, "SQLMap"),
            ScannerType::Subfinder => write!(f, "Subfinder"),
            ScannerType::Httpx => write!(f, "httpx"),
            ScannerType::Wpscan => write!(f, "WPScan"),
            ScannerType::Hydra => write!(f, "Hydra"),
        }
    }
}

impl FromStr for ScannerType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nmap" => Ok(ScannerType::Nmap),
            "nuclei" => Ok(ScannerType::Nuclei),
            "zap" => Ok(ScannerType::Zap),
            "feroxbuster" => Ok(ScannerType::Feroxbuster),
            "sqlmap" => Ok(ScannerType::Sqlmap),
            "subfinder" => Ok(ScannerType::Subfinder),
            "httpx" => Ok(ScannerType::Httpx),
            "wpscan" => Ok(ScannerType::Wpscan),
            "hydra" => Ok(ScannerType::Hydra),
            _ => Err(format!("Unknown scanner: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scanner: ScannerType,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub raw_output: String,
    pub findings: Vec<Finding>,
    pub success: bool,
    pub error: Option<String>,
}

pub async fn run_scanner(scanner_type: &ScannerType, target: &str) -> Result<ScanResult> {
    match scanner_type {
        ScannerType::Nmap => nmap::run(target).await,
        ScannerType::Nuclei => nuclei::run(target).await,
        ScannerType::Zap => zap::run(target).await,
        ScannerType::Feroxbuster => feroxbuster::run(target).await,
        ScannerType::Sqlmap => sqlmap::run(target).await,
        ScannerType::Subfinder => subfinder::run(target).await,
        ScannerType::Httpx => httpx::run(target).await,
        ScannerType::Wpscan => wpscan::run(target).await,
        ScannerType::Hydra => {
            // Hydra requires targets from Nmap; standalone run not supported
            Ok(ScanResult {
                scanner: ScannerType::Hydra,
                target: target.to_string(),
                started_at: chrono::Utc::now(),
                finished_at: chrono::Utc::now(),
                raw_output: String::new(),
                findings: Vec::new(),
                success: false,
                error: Some(
                    "Hydra runs as a post-scan chain after Nmap. Select both Nmap and Hydra."
                        .to_string(),
                ),
            })
        }
    }
}

/// Check if a tool is available in PATH
pub async fn check_tool(name: &str) -> bool {
    tokio::process::Command::new(if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    })
    .arg(name)
    .output()
    .await
    .map(|o| o.status.success())
    .unwrap_or(false)
}

/// Extract URLs from findings that look like SQL injection vulnerabilities
pub fn extract_sqli_targets(results: &[ScanResult]) -> Vec<String> {
    let sqli_keywords = [
        "sql injection",
        "sqli",
        "sql-injection",
        "sql_injection",
        "blind sql",
        "time-based sql",
        "error-based sql",
        "union-based sql",
    ];

    let mut targets = Vec::new();
    for result in results {
        if result.scanner != ScannerType::Zap && result.scanner != ScannerType::Nuclei {
            continue;
        }
        for finding in &result.findings {
            let title_lower = finding.title.to_lowercase();
            let desc_lower = finding.description.to_lowercase();
            if sqli_keywords
                .iter()
                .any(|kw| title_lower.contains(kw) || desc_lower.contains(kw))
            {
                // Extract URL from details field (where scanners typically store matched-at / endpoint)
                let url = if finding.details.starts_with("http") {
                    finding
                        .details
                        .split_whitespace()
                        .next()
                        .unwrap_or(&finding.details)
                        .to_string()
                } else if result.target.starts_with("http") {
                    result.target.clone()
                } else {
                    continue;
                };
                if !targets.contains(&url) {
                    targets.push(url);
                }
            }
        }
    }
    targets
}

/// Extract discovered subdomains from Subfinder results
pub fn extract_subdomains(results: &[ScanResult]) -> Vec<String> {
    let mut subdomains = Vec::new();
    for result in results {
        if result.scanner == ScannerType::Subfinder && result.success {
            for finding in &result.findings {
                let sub = finding.details.trim();
                if !sub.is_empty() && !subdomains.contains(&sub.to_string()) {
                    subdomains.push(sub.to_string());
                }
            }
        }
    }
    subdomains
}

/// Detect whether WordPress was found in scan results (httpx tech detection, nuclei, nmap, feroxbuster)
pub fn detect_wordpress(results: &[ScanResult]) -> bool {
    let wp_indicators = [
        "wordpress",
        "wp-content",
        "wp-includes",
        "wp-json",
        "wp-login",
        "wp-admin",
    ];
    for result in results {
        if !result.success {
            continue;
        }
        match result.scanner {
            ScannerType::Httpx
            | ScannerType::Nuclei
            | ScannerType::Nmap
            | ScannerType::Feroxbuster => {
                let raw_lower = result.raw_output.to_lowercase();
                if wp_indicators.iter().any(|kw| raw_lower.contains(kw)) {
                    return true;
                }
                for finding in &result.findings {
                    let combined = format!(
                        "{} {} {}",
                        finding.title, finding.description, finding.details
                    )
                    .to_lowercase();
                    if wp_indicators.iter().any(|kw| combined.contains(kw)) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Extract brute-forceable service targets from Nmap results.
/// Parses Nmap findings for open ports with known services (SSH, FTP, MySQL, etc.)
pub fn extract_hydra_targets(results: &[ScanResult], target: &str) -> Vec<hydra::HydraTarget> {
    let host = target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or(target)
        .to_string();

    let mut targets = Vec::new();
    for result in results {
        if result.scanner != ScannerType::Nmap || !result.success {
            continue;
        }
        for finding in &result.findings {
            // Nmap findings have title like "Open port: 22/tcp"
            if !finding.title.starts_with("Open port:") {
                continue;
            }
            let port_str = finding
                .title
                .trim_start_matches("Open port:")
                .trim()
                .split('/')
                .next()
                .unwrap_or("0");
            let port: u16 = port_str.parse().unwrap_or(0);
            if port == 0 {
                continue;
            }

            let service = &finding.details;
            if hydra::is_supported_service(service) {
                targets.push(hydra::HydraTarget {
                    host: host.clone(),
                    port,
                    service: service.clone(),
                });
            }
        }
    }
    targets
}
