use anyhow::{Context, Result};
use log::{error, info, warn};
use std::process::Stdio;
use tokio::process::Command;

use crate::scanners::{check_tool, ScannerType};

#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub scanner: ScannerType,
    pub installed: bool,
    pub install_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallStatus {
    Success,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct InstallProgress {
    pub scanner: ScannerType,
    pub status: InstallStatus,
    pub output: String,
}

// ---------------------------------------------------------------------------
// PATH refresh
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub fn refresh_path() {
    use std::env;

    info!("Refreshing PATH from Windows registry...");

    let machine_path = std::process::Command::new("cmd")
        .args([
            "/C",
            "reg",
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            "/v",
            "Path",
        ])
        .output()
        .ok()
        .and_then(|o| {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            extract_reg_value(&out)
        })
        .unwrap_or_default();

    let user_path = std::process::Command::new("cmd")
        .args(["/C", "reg", "query", r"HKCU\Environment", "/v", "Path"])
        .output()
        .ok()
        .and_then(|o| {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            extract_reg_value(&out)
        })
        .unwrap_or_default();

    if !machine_path.is_empty() || !user_path.is_empty() {
        let new_path = if !machine_path.is_empty() && !user_path.is_empty() {
            format!("{};{}", machine_path, user_path)
        } else {
            format!("{}{}", machine_path, user_path)
        };
        info!("Updated PATH ({} chars)", new_path.len());
        env::set_var("PATH", &new_path);
    } else {
        warn!("Could not read PATH from registry");
    }
}

#[cfg(target_os = "windows")]
fn extract_reg_value(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Path") || trimmed.starts_with("PATH") {
            if let Some(pos) = trimmed.find("REG_") {
                let after_type = &trimmed[pos..];
                if let Some(val_start) = after_type.find("    ") {
                    let value = after_type[val_start..].trim();
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
pub fn refresh_path() {
    if let Ok(output) = std::process::Command::new("sh")
        .args(["-c", "echo $PATH"])
        .output()
    {
        let new_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !new_path.is_empty() {
            std::env::set_var("PATH", &new_path);
        }
    }
}

// ---------------------------------------------------------------------------
// Tool checking
// ---------------------------------------------------------------------------

pub async fn check_all_tools(scanners: &[ScannerType]) -> Vec<ToolStatus> {
    refresh_path();

    let mut statuses = Vec::new();

    for scanner in scanners {
        let cmd_name = get_cmd_name(scanner);
        let installed = check_tool(cmd_name).await;
        let install_hint = get_install_hint(scanner);

        info!(
            "Tool check: {} ({}) — {}",
            scanner,
            cmd_name,
            if installed { "found" } else { "NOT found" }
        );

        statuses.push(ToolStatus {
            scanner: scanner.clone(),
            installed,
            install_hint,
        });
    }

    statuses
}

fn get_cmd_name(scanner: &ScannerType) -> &'static str {
    match scanner {
        ScannerType::Nmap => "nmap",
        ScannerType::Nuclei => "nuclei",
        ScannerType::Zap => {
            if cfg!(target_os = "windows") {
                "zap.bat"
            } else {
                "zaproxy"
            }
        }
        ScannerType::Feroxbuster => "feroxbuster",
        ScannerType::Sqlmap => "sqlmap",
        ScannerType::Subfinder => "subfinder",
        ScannerType::Httpx => "httpx",
    }
}

fn get_install_hint(scanner: &ScannerType) -> String {
    match scanner {
        ScannerType::Nmap => {
            if cfg!(target_os = "windows") {
                "Download installer from https://nmap.org/download.html#windows".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install nmap".to_string()
            } else {
                "sudo apt install nmap  (or)  sudo dnf install nmap".to_string()
            }
        }
        ScannerType::Nuclei => {
            if cfg!(target_os = "windows") {
                "Download from https://github.com/projectdiscovery/nuclei/releases".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install nuclei".to_string()
            } else {
                "sudo apt install nuclei".to_string()
            }
        }
        ScannerType::Zap => {
            if cfg!(target_os = "windows") {
                "Download from https://www.zaproxy.org/download/".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install --cask zap".to_string()
            } else {
                "sudo apt install zaproxy".to_string()
            }
        }
        ScannerType::Feroxbuster => {
            if cfg!(target_os = "windows") {
                "Download from https://github.com/epi052/feroxbuster/releases".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install feroxbuster".to_string()
            } else {
                "sudo apt install feroxbuster  (or)  cargo install feroxbuster".to_string()
            }
        }
        ScannerType::Sqlmap => {
            if cfg!(target_os = "windows") {
                "pip install sqlmap  (or)  https://sqlmap.org".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install sqlmap".to_string()
            } else {
                "sudo apt install sqlmap  (or)  pip install sqlmap".to_string()
            }
        }
        ScannerType::Subfinder => {
            if cfg!(target_os = "windows") {
                "Download from https://github.com/projectdiscovery/subfinder/releases".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install subfinder".to_string()
            } else {
                "sudo apt install subfinder  (or)  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest".to_string()
            }
        }
        ScannerType::Httpx => {
            if cfg!(target_os = "windows") {
                "Download from https://github.com/projectdiscovery/httpx/releases".to_string()
            } else if cfg!(target_os = "macos") {
                "brew install httpx".to_string()
            } else {
                "sudo apt install httpx  (or)  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Install methods
// ---------------------------------------------------------------------------

enum InstallMethod {
    /// A PowerShell script — will be written to a temp .ps1 file then executed
    PsScript(String),
    /// A simple command string
    ShellCmd(String),
}

fn get_install_method(scanner: &ScannerType) -> Option<InstallMethod> {
    match scanner {
        ScannerType::Nmap => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(nmap_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd("brew install nmap".to_string()))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y nmap || sudo dnf install -y nmap".to_string(),
                ))
            }
        }
        ScannerType::Nuclei => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(nuclei_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd("brew install nuclei".to_string()))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y nuclei || sudo snap install nuclei".to_string(),
                ))
            }
        }
        ScannerType::Zap => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(zap_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd(
                    "brew install --cask zap".to_string(),
                ))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y zaproxy".to_string(),
                ))
            }
        }
        ScannerType::Feroxbuster => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(feroxbuster_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd(
                    "brew install feroxbuster".to_string(),
                ))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y feroxbuster || cargo install feroxbuster".to_string(),
                ))
            }
        }
        ScannerType::Sqlmap => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::ShellCmd("pip install sqlmap".to_string()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd("brew install sqlmap".to_string()))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y sqlmap || pip install sqlmap".to_string(),
                ))
            }
        }
        ScannerType::Subfinder => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(subfinder_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd(
                    "brew install subfinder".to_string(),
                ))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y subfinder || go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest".to_string(),
                ))
            }
        }
        ScannerType::Httpx => {
            if cfg!(target_os = "windows") {
                Some(InstallMethod::PsScript(httpx_ps_script()))
            } else if cfg!(target_os = "macos") {
                Some(InstallMethod::ShellCmd("brew install httpx".to_string()))
            } else {
                Some(InstallMethod::ShellCmd(
                    "sudo apt-get install -y httpx || go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest".to_string(),
                ))
            }
        }
    }
}

fn nmap_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "",
        "# Check if Npcap is already installed (required for Nmap silent install)",
        "$npcapInstalled = $false",
        "if (Test-Path \"$env:SystemRoot\\System32\\Npcap\") { $npcapInstalled = $true }",
        "if (Get-Service npcap -ErrorAction SilentlyContinue) { $npcapInstalled = $true }",
        "",
        "if (-not $npcapInstalled) {",
        "    Write-Host 'Npcap is required for Nmap. Downloading Npcap installer...'",
        "    $npcapPage = Invoke-WebRequest -Uri 'https://npcap.com/' -UseBasicParsing",
        "    $npcapLink = $npcapPage.Links | Where-Object { $_.href -match 'npcap-[\\d.]+-?\\d*\\.exe$' } | Select-Object -First 1",
        "    if (-not $npcapLink) {",
        "        Write-Error 'Could not find Npcap installer URL'",
        "        exit 1",
        "    }",
        "    $npcapUrl = $npcapLink.href",
        "    if ($npcapUrl -notmatch '^https?://') { $npcapUrl = 'https://npcap.com/' + $npcapUrl.TrimStart('/') }",
        "    $npcapPath = Join-Path $env:TEMP 'npcap-setup.exe'",
        "    Write-Host \"Downloading $npcapUrl...\"",
        "    Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapPath -UseBasicParsing",
        "",
        "    # Run Npcap installer interactively (free edition has no silent mode)",
        "    Write-Host 'Launching Npcap installer — please complete the installation wizard...'",
        "    $npcapProc = Start-Process -FilePath $npcapPath -Verb RunAs -PassThru",
        "    $npcapProc.WaitForExit()",
        "    Write-Host \"Npcap installer exit code: $($npcapProc.ExitCode)\"",
        "    Remove-Item $npcapPath -Force -ErrorAction SilentlyContinue",
        "",
        "    # Verify Npcap installed",
        "    if (-not (Test-Path \"$env:SystemRoot\\System32\\Npcap\")) {",
        "        Write-Error 'Npcap installation failed or was cancelled'",
        "        exit 1",
        "    }",
        "    Write-Host 'Npcap installed successfully'",
        "} else {",
        "    Write-Host 'Npcap already installed'",
        "}",
        "",
        "# Install Visual C++ Redistributable 2013 x86 (MSVCR120.dll) — Nmap is 32-bit",
        "$needVc = $true",
        "if (Test-Path \"$env:SystemRoot\\SysWOW64\\msvcr120.dll\") { $needVc = $false }",
        "if (Test-Path \"$env:SystemRoot\\System32\\msvcr120.dll\") { $needVc = $false }",
        "if ($needVc) {",
        "    Write-Host 'Installing Visual C++ 2013 Redistributable (x86)...'",
        "    $vcUrl = 'https://aka.ms/highdpimfc2013x86enu'",
        "    $vcPath = Join-Path $env:TEMP 'vcredist_x86_2013.exe'",
        "    Invoke-WebRequest -Uri $vcUrl -OutFile $vcPath -UseBasicParsing",
        "    Start-Process -FilePath $vcPath -ArgumentList '/install /quiet /norestart' -Wait",
        "    Remove-Item $vcPath -Force",
        "    Write-Host 'Visual C++ 2013 Redistributable (x86) installed'",
        "} else {",
        "    Write-Host 'Visual C++ 2013 Redistributable already present'",
        "}",
        "",
        "# Download latest Nmap setup",
        "$page = Invoke-WebRequest -Uri 'https://nmap.org/download.html' -UseBasicParsing",
        "$link = $page.Links | Where-Object { $_.href -match 'nmap-[\\d.]+-setup\\.exe$' } | Select-Object -First 1",
        "if (-not $link) { Write-Error 'Could not find Nmap installer URL'; exit 1 }",
        "",
        "$downloadUrl = $link.href",
        "if ($downloadUrl -notmatch '^https?://') { $downloadUrl = 'https://nmap.org' + $downloadUrl }",
        "",
        "$setupPath = Join-Path $env:TEMP 'nmap-setup.exe'",
        "Write-Host \"Downloading $downloadUrl...\"",
        "Invoke-WebRequest -Uri $downloadUrl -OutFile $setupPath -UseBasicParsing",
        "",
        "# Silent install (needs elevation for Program Files)",
        "Write-Host 'Installing Nmap (requesting elevation)...'",
        "$proc = Start-Process -FilePath $setupPath -ArgumentList '/S' -Verb RunAs -PassThru",
        "$proc.WaitForExit()",
        "Write-Host \"Nmap installer exit code: $($proc.ExitCode)\"",
        "Remove-Item $setupPath -Force",
        "",
        "# Wait a moment for files to be written",
        "Start-Sleep -Seconds 3",
        "",
        "# Find nmap.exe and add its directory to user PATH",
        "$nmapPaths = @(",
        "    \"$env:ProgramFiles\\Nmap\"",
        "    \"${env:ProgramFiles(x86)}\\Nmap\"",
        "    \"$env:ProgramW6432\\Nmap\"",
        ")",
        "$nmapDir = $nmapPaths | Where-Object { Test-Path (Join-Path $_ 'nmap.exe') } | Select-Object -First 1",
        "",
        "if (-not $nmapDir) {",
        "    # Fallback: search common locations",
        "    $found = Get-ChildItem -Path \"$env:ProgramFiles\",\"${env:ProgramFiles(x86)}\" -Filter 'nmap.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1",
        "    if ($found) { $nmapDir = $found.DirectoryName }",
        "}",
        "",
        "if ($nmapDir) {",
        "    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "    if ($userPath -notlike \"*$nmapDir*\") {",
        "        [Environment]::SetEnvironmentVariable('Path', \"$userPath;$nmapDir\", 'User')",
        "        Write-Host \"Added $nmapDir to user PATH\"",
        "    } else {",
        "        Write-Host \"$nmapDir already in PATH\"",
        "    }",
        "    Write-Host \"Nmap installed to $nmapDir\"",
        "} else {",
        "    Write-Error 'Nmap installed but nmap.exe not found — please add it to PATH manually'",
        "    exit 1",
        "}",
    ]
    .join("\r\n")
}

fn zap_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "",
        "# Check Java 17+",
        "$needJava = $true",
        "try {",
        "    $javaCheck = Get-Command java -ErrorAction SilentlyContinue",
        "    if ($javaCheck) {",
        "        $javaVer = (& java -version 2>&1) | Out-String",
        "        if ($javaVer -match '(\\d+)\\.') { if ([int]$Matches[1] -ge 17) { $needJava = $false } }",
        "    }",
        "} catch { }",
        "",
        "if ($needJava) {",
        "    Write-Host 'Installing Java 17 (Eclipse Temurin JRE)...'",
        "    $javaProc = Start-Process powershell -Verb RunAs -PassThru -Wait -ArgumentList '-Command','winget install --accept-package-agreements --accept-source-agreements EclipseAdoptium.Temurin.17.JRE; exit $LASTEXITCODE'",
        "    Write-Host \"Java installer exit code: $($javaProc.ExitCode)\"",
        "    # Refresh PATH to pick up java",
        "    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')",
        "    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "    $env:Path = \"$machinePath;$userPath\"",
        "    $javaTest = Get-Command java -ErrorAction SilentlyContinue",
        "    if (-not $javaTest) { Write-Error 'Java 17 installation failed'; exit 1 }",
        "} else {",
        "    Write-Host 'Java 17+ already installed'",
        "}",
        "",
        "# Download ZAP cross-platform package from GitHub",
        "$installDir = Join-Path $env:LOCALAPPDATA 'zaproxy'",
        "$zipPath = Join-Path $env:TEMP 'zap.zip'",
        "",
        "Write-Host 'Fetching latest ZAP release from GitHub...'",
        "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/zaproxy/zaproxy/releases/latest'",
        "$asset = $release.assets | Where-Object { $_.name -match 'ZAP.*crossplatform.*\\.zip$' -or $_.name -match 'ZAP.*cross.platform.*\\.zip$' } | Select-Object -First 1",
        "if (-not $asset) {",
        "    # Fallback: look for the core cross-platform package",
        "    $asset = $release.assets | Where-Object { $_.name -match '\\.zip$' -and $_.name -notmatch 'weekly' } | Select-Object -First 1",
        "}",
        "if (-not $asset) { Write-Error 'Could not find ZAP cross-platform download'; exit 1 }",
        "",
        "Write-Host \"Downloading $($asset.browser_download_url) ($([math]::Round($asset.size / 1MB, 1)) MB)...\"",
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing",
        "",
        "# Extract",
        "Write-Host 'Extracting ZAP...'",
        "if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }",
        "Expand-Archive -Path $zipPath -DestinationPath $env:LOCALAPPDATA -Force",
        "Remove-Item $zipPath -Force",
        "",
        "# The archive extracts to a folder like ZAP_2.17.0 — rename it",
        "$extracted = Get-ChildItem -Path $env:LOCALAPPDATA -Directory | Where-Object { $_.Name -match '^ZAP' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1",
        "if ($extracted -and $extracted.FullName -ne $installDir) {",
        "    if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }",
        "    Rename-Item $extracted.FullName $installDir",
        "}",
        "",
        "# Verify zap.bat exists",
        "if (-not (Test-Path (Join-Path $installDir 'zap.bat'))) {",
        "    # Check if it's in a subdirectory",
        "    $found = Get-ChildItem -Path $installDir -Filter 'zap.bat' -Recurse -Depth 2 | Select-Object -First 1",
        "    if ($found) {",
        "        $installDir = $found.DirectoryName",
        "    } else {",
        "        Write-Error 'zap.bat not found after extraction'",
        "        exit 1",
        "    }",
        "}",
        "",
        "# Add to user PATH",
        "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "if ($userPath -notlike \"*$installDir*\") {",
        "    [Environment]::SetEnvironmentVariable('Path', \"$userPath;$installDir\", 'User')",
        "    Write-Host \"Added $installDir to user PATH\"",
        "}",
        "",
        "Write-Host \"ZAP installed to $installDir\"",
    ]
    .join("\r\n")
}

fn nuclei_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "$installDir = Join-Path $env:LOCALAPPDATA 'nuclei'",
        "$zipPath   = Join-Path $env:TEMP 'nuclei.zip'",
        "",
        "if (-not (Test-Path $installDir)) {",
        "    New-Item -ItemType Directory -Path $installDir -Force > $null",
        "}",
        "",
        "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/projectdiscovery/nuclei/releases/latest'",
        "$asset   = $release.assets | Where-Object { $_.name -match 'nuclei_.*_windows_amd64\\.zip$' } | Select-Object -First 1",
        "if (-not $asset) { Write-Error 'Could not find nuclei Windows release'; exit 1 }",
        "",
        "Write-Host \"Downloading $($asset.browser_download_url)...\"",
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing",
        "",
        "Expand-Archive -Path $zipPath -DestinationPath $installDir -Force",
        "Remove-Item $zipPath -Force",
        "",
        "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "if ($userPath -notlike \"*$installDir*\") {",
        "    [Environment]::SetEnvironmentVariable('Path', \"$userPath;$installDir\", 'User')",
        "    Write-Host \"Added $installDir to user PATH\"",
        "}",
        "",
        "Write-Host \"nuclei installed to $installDir\"",
    ]
    .join("\r\n")
}

fn feroxbuster_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "$installDir = Join-Path $env:LOCALAPPDATA 'feroxbuster'",
        "$zipPath   = Join-Path $env:TEMP 'feroxbuster.zip'",
        "",
        "if (-not (Test-Path $installDir)) {",
        "    New-Item -ItemType Directory -Path $installDir -Force > $null",
        "}",
        "",
        "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/epi052/feroxbuster/releases/latest'",
        "$asset   = $release.assets | Where-Object { $_.name -match '^x86_64-windows-feroxbuster' -and $_.name -notmatch 'debug' } | Select-Object -First 1",
        "if (-not $asset) { Write-Error 'Could not find feroxbuster Windows release'; exit 1 }",
        "",
        "Write-Host \"Downloading $($asset.browser_download_url)...\"",
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing",
        "",
        "Expand-Archive -Path $zipPath -DestinationPath $installDir -Force",
        "Remove-Item $zipPath -Force",
        "",
        "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "if ($userPath -notlike \"*$installDir*\") {",
        "    [Environment]::SetEnvironmentVariable('Path', \"$userPath;$installDir\", 'User')",
        "    Write-Host \"Added $installDir to user PATH\"",
        "}",
        "",
        "Write-Host \"feroxbuster installed to $installDir\"",
    ]
    .join("\r\n")
}

fn subfinder_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "$installDir = Join-Path $env:LOCALAPPDATA 'subfinder'",
        "$zipPath   = Join-Path $env:TEMP 'subfinder.zip'",
        "",
        "if (-not (Test-Path $installDir)) {",
        "    New-Item -ItemType Directory -Path $installDir -Force > $null",
        "}",
        "",
        "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/projectdiscovery/subfinder/releases/latest'",
        "$asset   = $release.assets | Where-Object { $_.name -match 'subfinder_.*_windows_amd64\\.zip$' } | Select-Object -First 1",
        "if (-not $asset) { Write-Error 'Could not find subfinder Windows release'; exit 1 }",
        "",
        "Write-Host \"Downloading $($asset.browser_download_url)...\"",
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing",
        "",
        "Expand-Archive -Path $zipPath -DestinationPath $installDir -Force",
        "Remove-Item $zipPath -Force",
        "",
        "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "if ($userPath -notlike \"*$installDir*\") {",
        "    [Environment]::SetEnvironmentVariable('Path', \"$userPath;$installDir\", 'User')",
        "    Write-Host \"Added $installDir to user PATH\"",
        "}",
        "",
        "Write-Host \"subfinder installed to $installDir\"",
    ]
    .join("\r\n")
}

fn httpx_ps_script() -> String {
    [
        "$ErrorActionPreference = 'Stop'",
        "$installDir = Join-Path $env:LOCALAPPDATA 'httpx'",
        "$zipPath   = Join-Path $env:TEMP 'httpx.zip'",
        "",
        "if (-not (Test-Path $installDir)) {",
        "    New-Item -ItemType Directory -Path $installDir -Force > $null",
        "}",
        "",
        "$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/projectdiscovery/httpx/releases/latest'",
        "$asset   = $release.assets | Where-Object { $_.name -match 'httpx_.*_windows_amd64\\.zip$' } | Select-Object -First 1",
        "if (-not $asset) { Write-Error 'Could not find httpx Windows release'; exit 1 }",
        "",
        "Write-Host \"Downloading $($asset.browser_download_url)...\"",
        "Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing",
        "",
        "Expand-Archive -Path $zipPath -DestinationPath $installDir -Force",
        "Remove-Item $zipPath -Force",
        "",
        "$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')",
        "if ($userPath -notlike \"*$installDir*\") {",
        "    [Environment]::SetEnvironmentVariable('Path', \"$userPath;$installDir\", 'User')",
        "    Write-Host \"Added $installDir to user PATH\"",
        "}",
        "",
        "Write-Host \"httpx installed to $installDir\"",
    ]
    .join("\r\n")
}

// ---------------------------------------------------------------------------
// Install execution
// ---------------------------------------------------------------------------

pub async fn install_tool(scanner: &ScannerType) -> Result<InstallProgress> {
    let method = match get_install_method(scanner) {
        Some(m) => m,
        None => {
            error!("No install method available for {}", scanner);
            return Ok(InstallProgress {
                scanner: scanner.clone(),
                status: InstallStatus::Failed("No install method available".to_string()),
                output: String::new(),
            });
        }
    };

    let output = match method {
        InstallMethod::PsScript(script) => {
            let script_file = tempfile::Builder::new()
                .prefix(&format!("octoscan_{}_", scanner.to_string().to_lowercase()))
                .suffix(".ps1")
                .tempfile()
                .context("Failed to create secure temp file for PS script")?;
            // Close the file handle before writing so PowerShell can read it on Windows
            let script_path = script_file.into_temp_path().to_path_buf();
            info!("Writing PS script to {}", script_path.display());
            std::fs::write(&script_path, &script)
                .context(format!("Failed to write {}", script_path.display()))?;

            info!("Executing PS script for {}", scanner);
            let result = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    &script_path.to_string_lossy(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .await
                .context("Failed to execute PowerShell script")?;

            let _ = std::fs::remove_file(&script_path);
            result
        }
        InstallMethod::ShellCmd(cmd) => {
            info!("Installing {} with: {}", scanner, cmd);

            if cfg!(target_os = "windows") {
                // Use powershell, NOT cmd.exe
                Command::new("powershell")
                    .args(["-NoProfile", "-Command", &cmd])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .await
                    .context(format!("Failed to run: {}", cmd))?
            } else {
                Command::new("sh")
                    .args(["-c", &cmd])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .await
                    .context(format!("Failed to run: {}", cmd))?
            }
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("=== STDOUT ===\n{}\n=== STDERR ===\n{}", stdout, stderr);
    let exit_code = output.status.code().unwrap_or(-1);

    info!("Install {} exit code: {}", scanner, exit_code);
    info!("Install {} stdout:\n{}", scanner, stdout);
    if !stderr.is_empty() {
        warn!("Install {} stderr:\n{}", scanner, stderr);
    }

    if output.status.success() {
        refresh_path();

        let cmd_name = get_cmd_name(scanner);
        let now_available = check_tool(cmd_name).await;

        if now_available {
            info!("{} is now available in PATH", scanner);
        } else {
            warn!("{} install succeeded (exit 0) but not yet in PATH", scanner);
        }

        // Consider success either way — PATH may need a terminal restart
        Ok(InstallProgress {
            scanner: scanner.clone(),
            status: InstallStatus::Success,
            output: combined,
        })
    } else {
        error!(
            "Install {} FAILED (exit {})\n{}",
            scanner, exit_code, combined
        );
        Ok(InstallProgress {
            scanner: scanner.clone(),
            status: InstallStatus::Failed(format!(
                "Exit code: {} — check logs for details",
                exit_code
            )),
            output: combined,
        })
    }
}
