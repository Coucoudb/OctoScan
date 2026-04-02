use anyhow::{Context, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

/// Find the directory containing zap.bat so we can set the working directory
fn find_zap_dir() -> Option<PathBuf> {
    if let Ok(output) = std::process::Command::new("where.exe")
        .arg("zap.bat")
        .output()
    {
        let path_str = String::from_utf8_lossy(&output.stdout);
        let path = PathBuf::from(path_str.lines().next()?.trim());
        return path.parent().map(|p| p.to_path_buf());
    }
    None
}

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    // Detect which ZAP command is available
    let (zap_cmd, is_zap_bat) = if check_tool("zap.bat").await {
        ("zap.bat", true)
    } else if check_tool("zap-cli").await {
        ("zap-cli", false)
    } else if check_tool("zaproxy").await {
        ("zaproxy", false)
    } else {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Zap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some(
                "ZAP (zap.bat, zap-cli, or zaproxy) is not installed or not in PATH".to_string(),
            ),
        });
    };

    let mut cmd = Command::new(zap_cmd);

    if is_zap_bat {
        // zap.bat / zap.sh uses native ZAP CLI args
        // Must run from ZAP's install directory so it finds the .jar
        if let Some(zap_dir) = find_zap_dir() {
            cmd.current_dir(&zap_dir);
        }
        cmd.args(["-cmd", "-quickurl", target, "-quickprogress"]);
    } else {
        // zap-cli style
        cmd.args(["quick-scan", "--self-contained", "-s", "xss,sqli", target]);
    }

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute ZAP")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Clean raw output: strip progress bars and carriage-return noise
    let clean_output = clean_zap_output(&raw_output);

    if !output.status.success() && clean_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Zap,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", clean_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("ZAP exited with status: {}", output.status)),
        });
    }

    let findings = parse_zap_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Zap,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output: clean_output,
        findings,
        success: true,
        error: None,
    })
}

/// Strip progress bars, carriage returns, and cmd.exe echo noise from ZAP output
fn clean_zap_output(raw: &str) -> String {
    let mut lines = Vec::new();
    for line in raw.split('\n') {
        let line = line.trim_end_matches('\r');
        // Skip progress bar lines (contain [=== or spinner chars at end)
        if line.contains("] 0%")
            || line.contains("] 1%")
            || line.contains("% |")
            || line.contains("% /")
            || line.contains("% -")
            || line.contains("% \\")
            || line.trim().starts_with('[') && line.contains('%')
        {
            continue;
        }
        // Skip empty lines and cmd.exe prompt lines
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("C:\\") && trimmed.contains('>') {
            continue;
        }
        // Skip raw XML (already parsed into findings)
        if trimmed.starts_with("<?xml")
            || trimmed.starts_with('<') && !trimmed.starts_with("<script")
        {
            continue;
        }
        lines.push(line.to_string());
    }
    lines.join("\n")
}

fn parse_zap_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Try parsing XML report (OWASPZAPReport format from -quickprogress)
    if output.contains("<OWASPZAPReport") {
        findings.extend(parse_zap_xml(output));
        if !findings.is_empty() {
            return findings;
        }
    }

    // Try parsing as JSON first (ZAP API JSON output)
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
        if let Some(alerts) = json["alerts"].as_array() {
            for alert in alerts {
                let name = alert["name"].as_str().unwrap_or("Unknown").to_string();
                let risk_str = alert["risk"].as_str().unwrap_or("Informational");
                let severity = match risk_str {
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    "Low" => Severity::Low,
                    _ => Severity::Info,
                };
                let description = alert["description"].as_str().unwrap_or("").to_string();
                let solution = alert["solution"].as_str().unwrap_or("").to_string();

                findings.push(Finding {
                    title: name,
                    severity,
                    description,
                    details: format!("Solution: {}", solution),
                });
            }
        }
        return findings;
    }

    // Fallback: parse line-based output (ZAP quick-scan / quickprogress)
    for line in output.lines() {
        let trimmed = line.trim();

        // ZAP native quick-scan output: WARN-NEW / FAIL-NEW / PASS lines
        if trimmed.starts_with("WARN-NEW:")
            || trimmed.starts_with("FAIL-NEW:")
            || trimmed.starts_with("WARN-INPROG:")
            || trimmed.starts_with("FAIL-INPROG:")
        {
            let severity = if trimmed.contains("FAIL") {
                Severity::High
            } else {
                Severity::Medium
            };
            // Format: "WARN-NEW: Cookie ... [10010] x1 url"
            let desc = trimmed
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or(trimmed)
                .trim();
            let title = if let Some(bracket_start) = desc.find('[') {
                desc[..bracket_start].trim().to_string()
            } else {
                desc.to_string()
            };

            findings.push(Finding {
                title,
                severity,
                description: desc.to_string(),
                details: String::new(),
            });
        } else if trimmed.starts_with("WARN") || trimmed.starts_with("FAIL") {
            let severity = if trimmed.starts_with("FAIL") {
                Severity::High
            } else {
                Severity::Medium
            };

            findings.push(Finding {
                title: trimmed.to_string(),
                severity,
                description: trimmed.to_string(),
                details: String::new(),
            });
        }
    }

    findings
}

/// Parse ZAP's OWASPZAPReport XML to extract alertitems
fn parse_zap_xml(xml: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Find the XML portion
    let xml_start = match xml.find("<?xml") {
        Some(pos) => pos,
        None => return findings,
    };
    let xml_content = &xml[xml_start..];

    // Extract each <alertitem>...</alertitem>
    let mut search_from = 0;
    while let Some(start) = xml_content[search_from..].find("<alertitem>") {
        let abs_start = search_from + start;
        if let Some(end) = xml_content[abs_start..].find("</alertitem>") {
            let abs_end = abs_start + end + "</alertitem>".len();
            let alert_xml = &xml_content[abs_start..abs_end];

            let name = extract_xml_tag(alert_xml, "name").unwrap_or_default();
            let riskcode = extract_xml_tag(alert_xml, "riskcode")
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);
            let desc = extract_xml_tag(alert_xml, "desc").unwrap_or_default();
            let solution = extract_xml_tag(alert_xml, "solution").unwrap_or_default();
            let riskdesc = extract_xml_tag(alert_xml, "riskdesc").unwrap_or_default();
            let cweid = extract_xml_tag(alert_xml, "cweid").unwrap_or_default();
            let count = extract_xml_tag(alert_xml, "count").unwrap_or_default();

            let severity = match riskcode {
                3 => Severity::High,
                2 => Severity::Medium,
                1 => Severity::Low,
                _ => Severity::Info,
            };

            // Decode HTML entities in description
            let desc_clean = decode_xml_entities(&desc);
            let solution_clean = decode_xml_entities(&solution);

            findings.push(Finding {
                title: name,
                severity,
                description: desc_clean,
                details: format!(
                    "Risk: {} | CWE: {} | Instances: {}\nSolution: {}",
                    riskdesc, cweid, count, solution_clean
                ),
            });

            search_from = abs_end;
        } else {
            break;
        }
    }

    findings
}

/// Extract text content of an XML tag (first occurrence)
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].to_string())
}

/// Decode common XML/HTML entities
fn decode_xml_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&#x2014;", "—")
        // Strip remaining HTML tags for cleaner display
        .split('<')
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part.to_string()
            } else if let Some(pos) = part.find('>') {
                part[pos + 1..].to_string()
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("")
        .trim()
        .to_string()
}
