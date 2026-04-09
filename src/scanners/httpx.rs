use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str, extra_args: &[String]) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("httpx").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Httpx,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("httpx is not installed or not in PATH".to_string()),
        });
    }

    let mut cmd = Command::new("httpx");
    cmd.args([
        "-u",
        target,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-threads",
        "50", // concurrency
        "-timeout",
        "10",              // per-request timeout
        "-cdn",            // detect CDN usage
        "-ip",             // extract IP addresses
        "-cname",          // extract CNAME records
        "-content-length", // show response size
        "-web-server",     // detect web server
        "-location",       // show redirect location
    ]);
    if !extra_args.is_empty() {
        cmd.args(extra_args);
    }
    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute httpx")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Httpx,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("httpx exited with status: {}", output.status)),
        });
    }

    let findings = parse_httpx_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Httpx,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_httpx_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            let url = json["url"].as_str().unwrap_or("unknown").to_string();
            let status_code = json["status_code"].as_i64().unwrap_or(0);
            let title = json["title"].as_str().unwrap_or("").to_string();

            let technologies: Vec<String> = json["tech"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let tech_str = if technologies.is_empty() {
                "None detected".to_string()
            } else {
                technologies.join(", ")
            };

            findings.push(Finding {
                title: format!("HTTP Probe: {} [{}]", url, status_code),
                severity: Severity::Info,
                description: format!(
                    "Title: {} | Technologies: {}",
                    if title.is_empty() { "N/A" } else { &title },
                    tech_str
                ),
                details: format!(
                    "{} | Status: {} | Title: {} | Tech: {}",
                    url, status_code, title, tech_str
                ),
            });
        }
    }

    findings
}

/// Run httpx on a list of targets (e.g. subdomains from Subfinder) via stdin pipe
pub async fn run_list(targets: &[String]) -> Result<ScanResult> {
    let started_at = Utc::now();
    let combined_target = format!("{} subdomains", targets.len());

    if !check_tool("httpx").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Httpx,
            target: combined_target,
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("httpx is not installed or not in PATH".to_string()),
        });
    }

    let mut child = Command::new("httpx")
        .args([
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            "-threads",
            "50",
            "-timeout",
            "10",
            "-cdn",
            "-ip",
            "-cname",
            "-content-length",
            "-web-server",
            "-location",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn httpx")?;

    // Write all targets to httpx stdin
    if let Some(mut stdin) = child.stdin.take() {
        let input = targets.join("\n");
        stdin.write_all(input.as_bytes()).await?;
        // stdin is dropped here, closing the pipe so httpx starts processing
    }

    let output = child
        .wait_with_output()
        .await
        .context("Failed to wait for httpx")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Httpx,
            target: combined_target,
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("httpx exited with status: {}", output.status)),
        });
    }

    let findings = parse_httpx_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Httpx,
        target: combined_target,
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/httpx/normal.jsonl");
        let findings = parse_httpx_output(input);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("https://example.com"));
        assert!(findings[0].title.contains("200"));
        assert!(findings[0].description.contains("Nginx, PHP"));
        assert!(findings[1].description.contains("None detected"));
    }

    #[test]
    fn parse_empty_output() {
        let input = include_str!("../../tests/fixtures/httpx/empty.jsonl");
        let findings = parse_httpx_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_malformed_output_skips_bad_lines() {
        let input = include_str!("../../tests/fixtures/httpx/malformed.jsonl");
        let findings = parse_httpx_output(input);
        // Only valid JSON lines produce findings
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("valid.example.com"));
        assert!(findings[1].title.contains("also-valid.example.com"));
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_httpx_output("");
        assert!(findings.is_empty());
    }
}
