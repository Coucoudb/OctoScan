use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::process::Command;

use crate::scanners::{check_tool, ScannerType};

#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub scanner: ScannerType,
    pub installed: bool,
    pub install_cmd: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    Pending,
    Installing,
    Success,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct InstallProgress {
    pub scanner: ScannerType,
    pub status: InstallStatus,
    pub output: String,
}

/// Check which tools are available and return their status
pub async fn check_all_tools(scanners: &[ScannerType]) -> Vec<ToolStatus> {
    let mut statuses = Vec::new();

    for scanner in scanners {
        let (cmd_name, install_cmd) = get_tool_info(scanner);
        let installed = check_tool(cmd_name).await;

        statuses.push(ToolStatus {
            scanner: scanner.clone(),
            installed,
            install_cmd: install_cmd.to_string(),
        });
    }

    statuses
}

/// Get the command name and install instructions for each scanner
fn get_tool_info(scanner: &ScannerType) -> (&'static str, String) {
    match scanner {
        ScannerType::Nmap => {
            let install = if cfg!(target_os = "windows") {
                "winget install Insecure.Nmap".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install nmap".to_string()
            } else {
                "sudo apt-get install -y nmap".to_string()
            };
            ("nmap", install)
        }
        ScannerType::Nuclei => {
            let install = if cfg!(target_os = "windows") {
                "winget install ProjectDiscovery.Nuclei".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install nuclei".to_string()
            } else {
                "sudo apt-get install -y nuclei || go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest".to_string()
            };
            ("nuclei", install)
        }
        ScannerType::Zap => {
            let install = if cfg!(target_os = "windows") {
                "winget install ZAP.ZAP".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install --cask zap".to_string()
            } else {
                "sudo apt-get install -y zaproxy".to_string()
            };
            let cmd = if cfg!(target_os = "windows") { "zap-cli" } else { "zaproxy" };
            (cmd, install)
        }
    }
}

/// Install a tool by running the appropriate system command
pub async fn install_tool(scanner: &ScannerType) -> Result<InstallProgress> {
    let (_cmd_name, install_cmd) = get_tool_info(scanner);

    let parts: Vec<&str> = install_cmd.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(InstallProgress {
            scanner: scanner.clone(),
            status: InstallStatus::Failed("No install command available".to_string()),
            output: String::new(),
        });
    }

    // On Windows use cmd /C, on Unix use sh -c for complex commands
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(["/C", &install_cmd])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!("Failed to run: {}", install_cmd))?
    } else {
        Command::new("sh")
            .args(["-c", &install_cmd])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .context(format!("Failed to run: {}", install_cmd))?
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{}\n{}", stdout, stderr);

    if output.status.success() {
        // Verify the tool is now available
        let (cmd_name, _) = get_tool_info(scanner);
        let now_available = check_tool(cmd_name).await;

        if now_available {
            Ok(InstallProgress {
                scanner: scanner.clone(),
                status: InstallStatus::Success,
                output: combined,
            })
        } else {
            Ok(InstallProgress {
                scanner: scanner.clone(),
                status: InstallStatus::Failed(
                    "Install command succeeded but tool not found in PATH. You may need to restart your terminal.".to_string(),
                ),
                output: combined,
            })
        }
    } else {
        Ok(InstallProgress {
            scanner: scanner.clone(),
            status: InstallStatus::Failed(format!("Exit code: {}", output.status)),
            output: combined,
        })
    }
}
