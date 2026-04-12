use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str, extra_args: &[String]) -> Result<ScanResult> {
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

    let mut cmd = Command::new("nmap");
    cmd.args([
        "-sV", // service/version detection
        "-sC", // default NSE scripts
        "--script",
        "vuln", // vulnerability detection scripts
        "--top-ports",
        "1000",
        "-T4",    // aggressive timing
        "--open", // only show open ports
        "-Pn",    // skip host discovery (ICMP often blocked)
        "--min-rate",
        "1000",
        host,
    ]);
    if !extra_args.is_empty() {
        cmd.args(extra_args);
    }
    let output = cmd
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
    let lines: Vec<&str> = output.lines().collect();
    let mut current_port = String::new();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Track current port context: "80/tcp open http Apache httpd 2.4.41"
        if trimmed.contains("/tcp") && trimmed.contains("open") {
            let parts: Vec<&str> = trimmed.splitn(4, char::is_whitespace).collect();
            let port = parts.first().unwrap_or(&"unknown");
            current_port = port.to_string();
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
            i += 1;
            continue;
        }

        // Detect NSE script header: "| http-slowloris-check:" or "| http-vuln-cve2021-41773:"
        if trimmed.starts_with("| ") && trimmed.ends_with(':') && !trimmed.contains("VULNERABLE") {
            let script_name = trimmed
                .trim_start_matches("| ")
                .trim_start_matches("|_")
                .trim_end_matches(':')
                .to_string();

            // Look ahead for VULNERABLE marker within this NSE block
            let mut j = i + 1;
            let mut found_vuln = false;
            let mut vuln_name = String::new();
            let mut vuln_state = String::new();
            let mut cve_ids = Vec::new();
            let mut description_lines = Vec::new();

            while j < lines.len() {
                let block_line = lines[j].trim();

                // Stop if we hit a new script header, port line, or non-pipe line
                if !block_line.starts_with('|') && !block_line.is_empty() {
                    break;
                }
                // Stop at next script header
                if block_line.starts_with("| ")
                    && block_line.ends_with(':')
                    && !block_line.contains("VULNERABLE")
                    && !block_line.contains("State:")
                    && !block_line.contains("IDs:")
                {
                    break;
                }
                if block_line.starts_with("|_")
                    && !block_line.contains("VULNERABLE")
                    && !block_line.contains("CVE")
                {
                    // Last line of a script block
                    let content = block_line.trim_start_matches("|_").trim();
                    if !content.is_empty() {
                        description_lines.push(content.to_string());
                    }
                    j += 1;
                    break;
                }

                let content = block_line
                    .trim_start_matches("|_")
                    .trim_start_matches("| ")
                    .trim_start_matches('|')
                    .trim();

                if content.contains("VULNERABLE") && !content.contains("State:") {
                    found_vuln = true;
                } else if content.starts_with("State:") {
                    vuln_state = content.trim_start_matches("State:").trim().to_string();
                } else if content.contains("CVE:") || content.starts_with("IDs:") {
                    // Extract CVE IDs like "IDs:  CVE:CVE-2021-41773"
                    for part in content.split_whitespace() {
                        if let Some(cve) = part.strip_prefix("CVE:") {
                            cve_ids.push(cve.to_string());
                        }
                    }
                } else if !content.is_empty()
                    && !content.starts_with("References:")
                    && !content.starts_with("http")
                    && !content.starts_with("Disclosure date:")
                {
                    if vuln_name.is_empty() && found_vuln {
                        vuln_name = content.to_string();
                    } else if !content.is_empty() {
                        description_lines.push(content.to_string());
                    }
                }

                j += 1;
            }

            if found_vuln {
                let title = if !vuln_name.is_empty() {
                    vuln_name.clone()
                } else {
                    format!("NSE vulnerability: {}", script_name)
                };

                let severity = if vuln_state == "VULNERABLE" {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let cve_str = if cve_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", cve_ids.join(", "))
                };

                let port_str = if current_port.is_empty() {
                    String::new()
                } else {
                    format!(" on {}", current_port)
                };

                let description = format!(
                    "{}{} — State: {}{}",
                    title,
                    port_str,
                    if vuln_state.is_empty() {
                        "UNKNOWN"
                    } else {
                        &vuln_state
                    },
                    cve_str,
                );

                let details = if description_lines.is_empty() {
                    format!(
                        "Script: {} | Port: {} | State: {}",
                        script_name, current_port, vuln_state
                    )
                } else {
                    format!(
                        "Script: {} | Port: {} | State: {} | {}",
                        script_name,
                        current_port,
                        vuln_state,
                        description_lines.join(" "),
                    )
                };

                findings.push(Finding {
                    title,
                    severity,
                    description,
                    details,
                });

                i = j;
                continue;
            }

            i = j;
            continue;
        }

        i += 1;
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/nmap/normal.txt");
        let findings = parse_nmap_output(input);
        assert_eq!(findings.len(), 3);
        assert!(findings[0].title.contains("22/tcp"));
        assert!(findings[1].title.contains("80/tcp"));
        assert!(findings[2].title.contains("443/tcp"));
        assert!(matches!(findings[0].severity, Severity::Info));
    }

    #[test]
    fn parse_empty_output() {
        let input = include_str!("../../tests/fixtures/nmap/empty.txt");
        let findings = parse_nmap_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_vuln_output() {
        let input = include_str!("../../tests/fixtures/nmap/vuln.txt");
        let findings = parse_nmap_output(input);
        // Should find open ports + vulnerability details
        let port_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.starts_with("Open port"))
            .collect();
        let vuln_findings: Vec<_> = findings
            .iter()
            .filter(|f| !f.title.starts_with("Open port"))
            .collect();
        assert_eq!(port_findings.len(), 3);
        assert_eq!(vuln_findings.len(), 2);
        // First vuln: CVE-2021-41773 path traversal (VULNERABLE)
        assert!(vuln_findings[0].title.contains("Path traversal"));
        assert!(vuln_findings[0].description.contains("CVE-2021-41773"));
        assert!(vuln_findings[0].description.contains("80/tcp"));
        assert!(matches!(vuln_findings[0].severity, Severity::High));
        // Second vuln: Slowloris (LIKELY VULNERABLE)
        assert!(vuln_findings[1].title.contains("Slowloris"));
        assert!(vuln_findings[1].description.contains("CVE-2007-6750"));
        assert!(vuln_findings[1].description.contains("LIKELY VULNERABLE"));
        assert!(matches!(vuln_findings[1].severity, Severity::Medium));
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_nmap_output("");
        assert!(findings.is_empty());
    }
}
