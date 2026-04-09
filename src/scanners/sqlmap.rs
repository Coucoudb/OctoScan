use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

/// Run sqlmap against a single target URL
pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("sqlmap").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Sqlmap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("sqlmap is not installed or not in PATH".to_string()),
        });
    }

    let output = Command::new("sqlmap")
        .args([
            "-u",
            target,
            "--batch",
            "--level=3", // test cookies, user-agent, referer
            "--risk=2",
            "--threads=4",
            "--random-agent",     // randomize user-agent (WAF evasion)
            "--smart",            // thorough tests only on positive heuristic
            "--technique=BEUSTQ", // all injection techniques
            "--crawl=3",          // crawl the site to discover injectable endpoints
            "--forms",            // parse and test forms
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute sqlmap")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // sqlmap may exit non-zero if no injection found — that's still a valid run
    let findings = parse_sqlmap_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Sqlmap,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output: format!("{}\n{}", raw_output, stderr),
        findings,
        success: true,
        error: None,
    })
}

/// Run sqlmap on multiple URLs (from SQL injection findings) and merge results
pub async fn run_on_targets(targets: &[String]) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("sqlmap").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Sqlmap,
            target: targets.join(", "),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("sqlmap is not installed or not in PATH".to_string()),
        });
    }

    let mut all_findings = Vec::new();
    let mut all_output = String::new();

    for target in targets {
        let output = Command::new("sqlmap")
            .args([
                "-u",
                target,
                "--batch",
                "--level=2",
                "--risk=2",
                "--threads=4",
                "--crawl=3",
                "--forms",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!("Failed to execute sqlmap on {}", target))?;

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        all_output.push_str(&format!("=== {} ===\n{}\n{}\n\n", target, raw, stderr));
        all_findings.extend(parse_sqlmap_output(&raw));
    }

    let finished_at = Utc::now();

    Ok(ScanResult {
        scanner: ScannerType::Sqlmap,
        target: targets.join(", "),
        started_at,
        finished_at,
        raw_output: all_output,
        findings: all_findings,
        success: true,
        error: None,
    })
}

fn parse_sqlmap_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut current_param = String::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Detect injectable parameter
        // e.g. "Parameter: id (GET)"
        if trimmed.starts_with("Parameter:") {
            current_param = trimmed.to_string();
        }

        // Detect injection type
        // e.g. "    Type: boolean-based blind"
        if trimmed.starts_with("Type:") && !current_param.is_empty() {
            let injection_type = trimmed.trim_start_matches("Type:").trim();

            let severity = if injection_type.contains("UNION") || injection_type.contains("stacked")
            {
                Severity::Critical
            } else {
                Severity::High
            };

            findings.push(Finding {
                title: format!("SQL Injection — {}", injection_type),
                severity,
                description: current_param.clone(),
                details: format!("Injection type: {}", injection_type),
            });
        }

        // Detect database info
        // e.g. "back-end DBMS: MySQL >= 5.0"
        if trimmed.starts_with("back-end DBMS:") {
            findings.push(Finding {
                title: "Database Identified".to_string(),
                severity: Severity::Info,
                description: trimmed.to_string(),
                details: String::new(),
            });
        }

        // Detect dumped data
        if trimmed.contains("dumped to") || trimmed.contains("entries dumped") {
            findings.push(Finding {
                title: "Data Extracted".to_string(),
                severity: Severity::Critical,
                description: trimmed.to_string(),
                details: String::new(),
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
        let input = include_str!("../../tests/fixtures/sqlmap/normal.txt");
        let findings = parse_sqlmap_output(input);
        // Should find: 2 injection types + 1 DBMS identification
        let sqli_findings: Vec<_> = findings.iter().filter(|f| f.title.starts_with("SQL Injection")).collect();
        let dbms_findings: Vec<_> = findings.iter().filter(|f| f.title == "Database Identified").collect();
        assert_eq!(sqli_findings.len(), 2);
        assert_eq!(dbms_findings.len(), 1);
        assert!(sqli_findings[0].title.contains("boolean-based blind"));
        assert!(sqli_findings[1].title.contains("time-based blind"));
    }

    #[test]
    fn parse_empty_output_no_injection() {
        let input = include_str!("../../tests/fixtures/sqlmap/empty.txt");
        let findings = parse_sqlmap_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_union_and_dump_output() {
        let input = include_str!("../../tests/fixtures/sqlmap/union_and_dump.txt");
        let findings = parse_sqlmap_output(input);
        // UNION and stacked queries should be Critical severity
        let critical_findings: Vec<_> = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).collect();
        assert!(critical_findings.len() >= 2); // UNION sqli + stacked sqli + data extracted
        // Should detect data dump
        let dump_findings: Vec<_> = findings.iter().filter(|f| f.title == "Data Extracted").collect();
        assert!(!dump_findings.is_empty());
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_sqlmap_output("");
        assert!(findings.is_empty());
    }
}
