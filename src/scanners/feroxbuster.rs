use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

/// Returns the path to the default wordlist shipped by the installer.
fn default_wordlist() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let p = PathBuf::from(local)
                .join("feroxbuster")
                .join("wordlists")
                .join("raft-medium-directories.txt");
            if p.exists() {
                return Some(p);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let p =
            PathBuf::from("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

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

    let mut args = vec![
        "-u".to_string(),
        target.to_string(),
        "--silent".to_string(),
        "--no-state".to_string(),
        "--auto-tune".to_string(),
        "--json".to_string(),
        "-d".to_string(),
        "2".to_string(), // recursion depth limit
        "-t".to_string(),
        "50".to_string(), // threads
        "-k".to_string(), // skip TLS cert verification
        "--filter-status".to_string(),
        "404".to_string(), // filter out 404s
        "--timeout".to_string(),
        "10".to_string(), // request timeout (seconds)
    ];

    if let Some(wordlist) = default_wordlist() {
        args.push("-w".to_string());
        args.push(wordlist.to_string_lossy().to_string());
    }

    let output = Command::new("feroxbuster")
        .args(&args)
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

/// File extensions that indicate static assets (not interesting endpoints).
const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
];

/// Returns true if the URL path points to a static asset.
fn is_static_asset(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_lowercase();
    STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

/// Returns true if the URL contains excessive percent-encoding (garbage/binary).
fn is_garbage_url(url: &str) -> bool {
    let encoded_count =
        url.matches("%EF%BF%BD").count() + url.matches("%00").count() + url.matches("%C9").count();
    encoded_count >= 3
}

fn parse_feroxbuster_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen_urls: HashSet<String> = HashSet::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let obj_type = json["type"].as_str().unwrap_or("");
            if obj_type != "response" {
                continue;
            }

            let url = json["url"].as_str().unwrap_or("unknown").to_string();
            let status = json["status"].as_u64().unwrap_or(0);
            let content_length = json["content_length"].as_u64().unwrap_or(0);
            let method = json["method"].as_str().unwrap_or("GET");

            // Skip error responses (catch-all routes, bad requests)
            if status >= 400 && status != 401 && status != 403 {
                continue;
            }

            // Skip static assets
            if is_static_asset(&url) {
                continue;
            }

            // Skip garbage/binary URLs
            if is_garbage_url(&url) {
                continue;
            }

            // Deduplicate case-insensitively
            let url_lower = url.to_lowercase();
            if !seen_urls.insert(url_lower) {
                continue;
            }

            let severity = match status {
                200 => Severity::Info,
                301 | 302 => Severity::Low,
                401 | 403 => Severity::Medium,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/feroxbuster/normal.jsonl");
        let findings = parse_feroxbuster_output(input);
        assert_eq!(findings.len(), 3);
        assert!(findings[0].title.contains("200"));
        assert!(findings[0].title.contains("/admin"));
        assert!(findings[1].title.contains("403"));
        assert!(matches!(findings[1].severity, Severity::Medium));
        assert!(findings[2].title.contains("301"));
        assert!(matches!(findings[2].severity, Severity::Low));
    }

    #[test]
    fn parse_empty_output() {
        let input = include_str!("../../tests/fixtures/feroxbuster/empty.jsonl");
        let findings = parse_feroxbuster_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_filtered_output_skips_static_and_garbage() {
        let input = include_str!("../../tests/fixtures/feroxbuster/filtered.jsonl");
        let findings = parse_feroxbuster_output(input);
        // Should skip: .css, .png, 500 status, garbage URL, statistics type
        // Should keep: /real-endpoint
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("real-endpoint"));
    }

    #[test]
    fn is_static_asset_detection() {
        assert!(is_static_asset("http://example.com/style.css"));
        assert!(is_static_asset("http://example.com/logo.PNG"));
        assert!(!is_static_asset("http://example.com/api/users"));
    }

    #[test]
    fn is_garbage_url_detection() {
        assert!(is_garbage_url(
            "http://example.com/%EF%BF%BD%EF%BF%BD%EF%BF%BD"
        ));
        assert!(!is_garbage_url("http://example.com/normal-path"));
    }
}
