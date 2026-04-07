use anyhow::{Context, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

/// Known service names that Hydra supports, mapped from common nmap service strings.
const SUPPORTED_SERVICES: &[&str] = &[
    "ssh", "ftp", "http", "https", "mysql", "mssql", "postgres", "rdp", "smb", "smtp", "pop3",
    "imap", "telnet", "vnc", "ldap", "snmp",
];

/// A brute-force target extracted from Nmap results.
#[derive(Debug, Clone)]
pub struct HydraTarget {
    pub host: String,
    pub port: u16,
    pub service: String,
}

/// Returns the path to the default username wordlist.
fn default_userlist() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let p = PathBuf::from(local)
                .join("hydra")
                .join("wordlists")
                .join("top-usernames-shortlist.txt");
            if p.exists() {
                return Some(p);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let p = PathBuf::from("/usr/share/seclists/Usernames/top-usernames-shortlist.txt");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Returns the path to the default password wordlist.
fn default_passlist() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let p = PathBuf::from(local)
                .join("hydra")
                .join("wordlists")
                .join("Pwdb_top-10000.txt");
            if p.exists() {
                return Some(p);
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let p =
            PathBuf::from("/usr/share/seclists/Passwords/Common-Credentials/Pwdb_top-10000.txt");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Run Hydra against multiple service targets discovered by Nmap.
pub async fn run_on_targets(targets: &[HydraTarget]) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("hydra").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::Hydra,
            target: format!("{} service(s)", targets.len()),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("hydra is not installed or not in PATH".to_string()),
        });
    }

    let userlist = match default_userlist() {
        Some(p) => p,
        None => {
            let finished_at = Utc::now();
            return Ok(ScanResult {
                scanner: ScannerType::Hydra,
                target: format!("{} service(s)", targets.len()),
                started_at,
                finished_at,
                raw_output: String::new(),
                findings: Vec::new(),
                success: false,
                error: Some("User wordlist not found. Re-run the installer.".to_string()),
            });
        }
    };

    let passlist = match default_passlist() {
        Some(p) => p,
        None => {
            let finished_at = Utc::now();
            return Ok(ScanResult {
                scanner: ScannerType::Hydra,
                target: format!("{} service(s)", targets.len()),
                started_at,
                finished_at,
                raw_output: String::new(),
                findings: Vec::new(),
                success: false,
                error: Some("Password wordlist not found. Re-run the installer.".to_string()),
            });
        }
    };

    let mut all_findings = Vec::new();
    let mut all_output = String::new();

    for target in targets {
        let service = map_service(&target.service);

        let output = Command::new("hydra")
            .args([
                "-L",
                &userlist.to_string_lossy(),
                "-P",
                &passlist.to_string_lossy(),
                "-s",
                &target.port.to_string(),
                "-t",
                "4",  // max 4 parallel connections per target
                "-f", // stop after first valid pair found
                "-o",
                "-", // output to stdout
                &target.host,
                &service,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!(
                "Failed to execute hydra on {}:{}",
                target.host, target.port
            ))?;

        let raw = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        all_output.push_str(&format!(
            "=== {}:{} ({}) ===\n{}\n{}\n\n",
            target.host, target.port, service, raw, stderr
        ));

        all_findings.extend(parse_hydra_output(
            &raw,
            &target.host,
            target.port,
            &service,
        ));
    }

    let finished_at = Utc::now();

    Ok(ScanResult {
        scanner: ScannerType::Hydra,
        target: format!("{} service(s)", targets.len()),
        started_at,
        finished_at,
        raw_output: all_output,
        findings: all_findings,
        success: true,
        error: None,
    })
}

/// Map nmap service names to hydra module names.
fn map_service(nmap_service: &str) -> String {
    let s = nmap_service.to_lowercase();
    if s.contains("ssh") {
        "ssh".to_string()
    } else if s.contains("ftp") {
        "ftp".to_string()
    } else if s.contains("mysql") {
        "mysql".to_string()
    } else if s.contains("ms-sql") || s.contains("mssql") {
        "mssql".to_string()
    } else if s.contains("postgres") {
        "postgres".to_string()
    } else if s.contains("rdp") || s.contains("ms-wbt-server") {
        "rdp".to_string()
    } else if s.contains("smb") || s.contains("microsoft-ds") || s.contains("netbios") {
        "smb".to_string()
    } else if s.contains("smtp") {
        "smtp".to_string()
    } else if s.contains("pop3") {
        "pop3".to_string()
    } else if s.contains("imap") {
        "imap".to_string()
    } else if s.contains("telnet") {
        "telnet".to_string()
    } else if s.contains("vnc") {
        "vnc".to_string()
    } else if s.contains("ldap") {
        "ldap".to_string()
    } else if s.contains("https") {
        "https-get".to_string()
    } else if s.contains("http") {
        "http-get".to_string()
    } else {
        s
    }
}

/// Parse hydra stdout for successful credential findings.
/// Hydra output lines look like:
///   [22][ssh] host: 10.0.0.1   login: admin   password: admin123
fn parse_hydra_output(output: &str, host: &str, port: u16, service: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Successful login line
        if trimmed.contains("login:") && trimmed.contains("password:") {
            let login = extract_field(trimmed, "login:");
            let password = extract_field(trimmed, "password:");

            findings.push(Finding {
                title: format!("Weak credentials found — {}:{} ({})", host, port, service),
                severity: Severity::Critical,
                description: format!(
                    "Hydra found valid credentials on {}:{} ({}) — {}:{}",
                    host, port, service, login, password
                ),
                details: format!(
                    "host={} port={} service={} login={} password={}",
                    host, port, service, login, password
                ),
            });
        }
    }

    findings
}

fn extract_field(line: &str, field: &str) -> String {
    if let Some(pos) = line.find(field) {
        let after = &line[pos + field.len()..];
        after.split_whitespace().next().unwrap_or("").to_string()
    } else {
        String::new()
    }
}

/// Check if a service from nmap is something Hydra can brute-force.
pub fn is_supported_service(service: &str) -> bool {
    let s = service.to_lowercase();
    SUPPORTED_SERVICES.iter().any(|sup| s.contains(sup))
        || s.contains("ms-wbt-server")
        || s.contains("microsoft-ds")
        || s.contains("netbios")
}
