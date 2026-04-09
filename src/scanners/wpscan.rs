use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str) -> Result<ScanResult> {
    let started_at = Utc::now();

    let wpscan_cmd = if cfg!(target_os = "windows") {
        "wpscan.bat"
    } else {
        "wpscan"
    };

    if !check_tool(wpscan_cmd).await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Wpscan,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("wpscan is not installed or not in PATH".to_string()),
        });
    }

    let mut cmd = Command::new(wpscan_cmd);

    // On Windows, WPScan needs libcurl from MSYS2 ucrt64/bin.
    // MSYS2 ships "libcurl-4.dll" but ethon/FFI looks for "curl" (→ libcurl.dll).
    // We fix this by setting ETHON_CURL_LIB and adding ucrt64/bin to PATH.
    #[cfg(target_os = "windows")]
    {
        let current_path = std::env::var("PATH").unwrap_or_default();
        let msys2_paths = find_msys2_bin_paths();
        if !msys2_paths.is_empty() {
            let new_path = format!("{};{}", msys2_paths.join(";"), current_path);
            cmd.env("PATH", new_path);
            // Point ethon directly to the MSYS2 libcurl DLL
            for p in &msys2_paths {
                let dll = std::path::Path::new(p).join("libcurl-4.dll");
                if dll.exists() {
                    cmd.env("ETHON_CURL_LIB", dll.to_string_lossy().to_string());
                    break;
                }
            }
        }
    }

    let output = cmd
        .args([
            "--url",
            target,
            "--format",
            "json",
            "--no-banner",
            "--random-user-agent",
            "--enumerate",
            "vp,vt,u1-20,dbe", // vulnerable plugins, themes, users, db exports
            "--detection-mode",
            "aggressive",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to execute wpscan")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // WPScan exits with code 5 when vulnerabilities are found — still valid
    if !output.status.success() && raw_output.is_empty() {
        return Ok(ScanResult {
            scanner: ScannerType::Wpscan,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("wpscan exited with status: {}", output.status)),
        });
    }

    let findings = parse_wpscan_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::Wpscan,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_wpscan_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    // WordPress version
    if let Some(version) = json.get("version") {
        let number = version["number"].as_str().unwrap_or("unknown");
        let status = version["status"].as_str().unwrap_or("unknown");
        let severity = if status == "outdated" {
            Severity::Medium
        } else {
            Severity::Info
        };
        findings.push(Finding {
            title: format!("WordPress {}", number),
            severity,
            description: format!("WordPress version {} ({})", number, status),
            details: format!("Status: {}", status),
        });

        // Version-level vulnerabilities
        if let Some(vulns) = version["vulnerabilities"].as_array() {
            for vuln in vulns {
                findings.push(parse_vulnerability(vuln));
            }
        }
    }

    // Main theme
    if let Some(theme) = json.get("main_theme") {
        parse_extension(&mut findings, theme, "Theme");
    }

    // Plugins
    if let Some(plugins) = json.get("plugins").and_then(|p| p.as_object()) {
        for (_name, plugin) in plugins {
            parse_extension(&mut findings, plugin, "Plugin");
        }
    }

    // Themes (enumerated)
    if let Some(themes) = json.get("themes").and_then(|t| t.as_object()) {
        for (_name, theme) in themes {
            parse_extension(&mut findings, theme, "Theme");
        }
    }

    // Users
    if let Some(users) = json.get("users").and_then(|u| u.as_object()) {
        for (username, _) in users {
            findings.push(Finding {
                title: format!("User: {}", username),
                severity: Severity::Info,
                description: format!("Enumerated WordPress user: {}", username),
                details: username.clone(),
            });
        }
    }

    findings
}

fn parse_extension(findings: &mut Vec<Finding>, ext: &serde_json::Value, kind: &str) {
    let slug = ext["slug"].as_str().unwrap_or("unknown");
    let version = ext["version"].as_str().unwrap_or("unknown");
    let outdated = ext["outdated"].as_bool().unwrap_or(false);

    let severity = if outdated {
        Severity::Low
    } else {
        Severity::Info
    };

    findings.push(Finding {
        title: format!(
            "{}: {} v{}{}",
            kind,
            slug,
            version,
            if outdated { " (outdated)" } else { "" }
        ),
        severity,
        description: format!("{} {} version {}", kind, slug, version),
        details: format!("Outdated: {}", outdated),
    });

    if let Some(vulns) = ext["vulnerabilities"].as_array() {
        for vuln in vulns {
            findings.push(parse_vulnerability(vuln));
        }
    }
}

fn parse_vulnerability(vuln: &serde_json::Value) -> Finding {
    let title = vuln["title"].as_str().unwrap_or("Unknown vulnerability");
    let vuln_type = vuln["vuln_type"].as_str().unwrap_or("");

    let references: Vec<String> = vuln["references"]["url"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let severity = match vuln_type.to_lowercase().as_str() {
        "rce" => Severity::Critical,
        "sqli" | "authbypass" => Severity::High,
        "xss" | "csrf" | "ssrf" => Severity::Medium,
        "lfi" | "redirect" => Severity::Medium,
        _ => Severity::High, // default to High for unknown vuln types
    };

    Finding {
        title: title.to_string(),
        severity,
        description: format!(
            "Type: {}",
            if vuln_type.is_empty() {
                "N/A"
            } else {
                vuln_type
            }
        ),
        details: if references.is_empty() {
            "No references".to_string()
        } else {
            references.join(", ")
        },
    }
}

/// Find MSYS2 ucrt64/bin paths for libcurl.dll on Windows
#[cfg(target_os = "windows")]
fn find_msys2_bin_paths() -> Vec<String> {
    let mut paths = Vec::new();
    let candidates = [
        "C:\\Ruby32-x64\\msys64\\ucrt64\\bin",
        "C:\\Ruby33-x64\\msys64\\ucrt64\\bin",
        "C:\\Ruby31-x64\\msys64\\ucrt64\\bin",
    ];
    for candidate in &candidates {
        if std::path::Path::new(candidate).exists() {
            paths.push(candidate.to_string());
        }
    }
    // Also try to derive from ruby location
    if paths.is_empty() {
        if let Ok(output) = std::process::Command::new("where.exe")
            .arg("ruby.exe")
            .output()
        {
            let ruby_path = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = ruby_path.lines().next() {
                let ruby_dir = std::path::Path::new(line.trim());
                if let Some(parent) = ruby_dir.parent().and_then(|p| p.parent()) {
                    let msys2_bin = parent.join("msys64").join("ucrt64").join("bin");
                    if msys2_bin.exists() {
                        paths.push(msys2_bin.to_string_lossy().to_string());
                    }
                }
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/wpscan/normal.json");
        let findings = parse_wpscan_output(input);
        // WordPress version + theme + plugin + 2 users
        assert!(findings.len() >= 4);
        assert!(findings[0].title.contains("WordPress 6.4.2"));
        assert!(matches!(findings[0].severity, Severity::Info)); // latest
        let user_findings: Vec<_> = findings.iter().filter(|f| f.title.starts_with("User:")).collect();
        assert_eq!(user_findings.len(), 2);
    }

    #[test]
    fn parse_empty_output_invalid_json() {
        let input = include_str!("../../tests/fixtures/wpscan/empty.json");
        let findings = parse_wpscan_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_vulnerable_output() {
        let input = include_str!("../../tests/fixtures/wpscan/vulnerable.json");
        let findings = parse_wpscan_output(input);
        // Should find: WP version (outdated), RCE vuln, theme + XSS vuln, plugin + LFI + SQLi vulns, user
        let vuln_count = findings.iter().filter(|f| !matches!(f.severity, Severity::Info) && !matches!(f.severity, Severity::Low)).count();
        assert!(vuln_count >= 3); // RCE (Critical), XSS (Medium), LFI (Medium), SQLi (High)
        // WordPress should be marked as outdated (Medium)
        assert!(matches!(findings[0].severity, Severity::Medium));
        assert!(findings[0].title.contains("5.2.1"));
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_wpscan_output("");
        assert!(findings.is_empty());
    }
}
