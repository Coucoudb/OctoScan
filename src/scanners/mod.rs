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
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

pub async fn run_scanner(
    scanner_type: &ScannerType,
    target: &str,
    extra_args: &[String],
) -> Result<ScanResult> {
    match scanner_type {
        ScannerType::Nmap => nmap::run(target, extra_args).await,
        ScannerType::Nuclei => nuclei::run(target, extra_args).await,
        ScannerType::Zap => zap::run(target, extra_args).await,
        ScannerType::Feroxbuster => feroxbuster::run(target, extra_args).await,
        ScannerType::Sqlmap => sqlmap::run(target, extra_args).await,
        ScannerType::Subfinder => subfinder::run(target, extra_args).await,
        ScannerType::Httpx => httpx::run(target, extra_args).await,
        ScannerType::Wpscan => wpscan::run(target, extra_args).await,
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

/// Characters that are forbidden in scanner arguments to prevent shell injection.
const FORBIDDEN_CHARS: &[char] = &[
    ';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r',
];

/// Validate that a single argument token does not contain shell metacharacters.
fn is_safe_arg(arg: &str) -> bool {
    !arg.chars().any(|c| FORBIDDEN_CHARS.contains(&c))
}

/// Split a raw argument string into tokens and validate each one.
/// Returns `Ok(Vec<String>)` on success or `Err(reason)` if any token is unsafe.
pub fn validate_and_split_args(raw: &str) -> std::result::Result<Vec<String>, String> {
    let tokens: Vec<String> = shell_words_split(raw);
    for token in &tokens {
        if !is_safe_arg(token) {
            return Err(format!(
                "Unsafe argument rejected: {:?} — shell metacharacters (;|&`$(){{}}< >) are not allowed",
                token
            ));
        }
    }
    Ok(tokens)
}

/// Parse CLI `--scanner-args` values ("scanner=args") into a per-scanner map.
/// Each value has the form "nmap=-sV --script=vuln".
pub fn parse_scanner_args(
    raw_args: &[String],
) -> std::result::Result<HashMap<ScannerType, Vec<String>>, String> {
    let mut map: HashMap<ScannerType, Vec<String>> = HashMap::new();
    for entry in raw_args {
        let (scanner_name, args_str) = entry.split_once('=').ok_or_else(|| {
            format!(
                "Invalid --scanner-args format: {:?}. Expected \"scanner=args\"",
                entry
            )
        })?;
        let scanner_type: ScannerType = scanner_name.parse().map_err(|e: String| e)?;
        let args = validate_and_split_args(args_str)?;
        map.entry(scanner_type).or_default().extend(args);
    }
    Ok(map)
}

/// Simple shell-like word splitting that respects double and single quotes.
/// Does NOT invoke a shell — purely in-process string splitting.
fn shell_words_split(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for ch in s.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
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

#[cfg(test)]
mod scanner_args_tests {
    use super::*;

    #[test]
    fn split_simple_args() {
        let tokens = shell_words_split("-sV --script=vuln --top-ports 1000");
        assert_eq!(tokens, vec!["-sV", "--script=vuln", "--top-ports", "1000"]);
    }

    #[test]
    fn split_quoted_args() {
        let tokens = shell_words_split(r#"-tags "cve,xss" --severity high"#);
        assert_eq!(tokens, vec!["-tags", "cve,xss", "--severity", "high"]);
    }

    #[test]
    fn split_single_quoted_args() {
        let tokens = shell_words_split("-w '/path/to/wordlist.txt' -d 3");
        assert_eq!(tokens, vec!["-w", "/path/to/wordlist.txt", "-d", "3"]);
    }

    #[test]
    fn split_empty_string() {
        let tokens = shell_words_split("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn validate_safe_args() {
        let result = validate_and_split_args("-sV --script=vuln --top-ports 1000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 4);
    }

    #[test]
    fn validate_rejects_semicolon() {
        let result = validate_and_split_args("-sV; rm -rf /");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsafe argument"));
    }

    #[test]
    fn validate_rejects_pipe() {
        let result = validate_and_split_args("-sV | cat /etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_backtick() {
        let result = validate_and_split_args("`whoami`");
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_dollar() {
        let result = validate_and_split_args("$(id)");
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_ampersand() {
        let result = validate_and_split_args("-sV && echo pwned");
        assert!(result.is_err());
    }

    #[test]
    fn parse_scanner_args_valid() {
        let raw = vec![
            "nmap=-sV --script=vuln".to_string(),
            "nuclei=-tags cve".to_string(),
        ];
        let result = parse_scanner_args(&raw);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(
            map.get(&ScannerType::Nmap).unwrap(),
            &vec!["-sV", "--script=vuln"]
        );
        assert_eq!(
            map.get(&ScannerType::Nuclei).unwrap(),
            &vec!["-tags", "cve"]
        );
    }

    #[test]
    fn parse_scanner_args_invalid_scanner_name() {
        let raw = vec!["notascanner=-sV".to_string()];
        let result = parse_scanner_args(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown scanner"));
    }

    #[test]
    fn parse_scanner_args_missing_equals() {
        let raw = vec!["nmap -sV".to_string()];
        let result = parse_scanner_args(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expected"));
    }

    #[test]
    fn parse_scanner_args_rejects_injection() {
        let raw = vec!["nmap=-sV; rm -rf /".to_string()];
        let result = parse_scanner_args(&raw);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsafe argument"));
    }

    #[test]
    fn parse_scanner_args_empty() {
        let raw: Vec<String> = vec![];
        let result = parse_scanner_args(&raw);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_scanner_args_merges_multiple_entries() {
        let raw = vec!["nmap=-sV".to_string(), "nmap=--top-ports 100".to_string()];
        let result = parse_scanner_args(&raw);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(
            map.get(&ScannerType::Nmap).unwrap(),
            &vec!["-sV", "--top-ports", "100"]
        );
    }
}
