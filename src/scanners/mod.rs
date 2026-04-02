pub mod nmap;
pub mod nuclei;
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
}

impl std::fmt::Display for ScannerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannerType::Nmap => write!(f, "Nmap"),
            ScannerType::Nuclei => write!(f, "Nuclei"),
            ScannerType::Zap => write!(f, "ZAP"),
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
    }
}

/// Check if a tool is available in PATH
pub async fn check_tool(name: &str) -> bool {
    tokio::process::Command::new(if cfg!(target_os = "windows") { "where" } else { "which" })
        .arg(name)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}
