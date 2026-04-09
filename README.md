```
  ██████╗  ██████╗████████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║        ██║   ██║   ██║███████╗██║     ███████║██╔██╗ ██║
 ██║   ██║██║        ██║   ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╗   ██║   ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Open Source](https://img.shields.io/badge/Open%20Source-%E2%9D%A4-green?style=for-the-badge)
![GitHub Stars](https://img.shields.io/github/stars/Coucoudb/OctoScan?style=for-the-badge&color=yellow)
![Security Audit](https://img.shields.io/badge/Security-Audit-blue?style=for-the-badge&logo=opensourceinitiative&logoColor=white)
![Bug Bounty](https://img.shields.io/badge/Bug%20Bounty-Tool-orange?style=for-the-badge&logo=hackerone&logoColor=white)

OctoScan is a CLI wrapper that orchestrates popular security tools (Nmap, Nuclei, ZAP, Feroxbuster, SQLMap, Subfinder, httpx, WPScan, Hydra) for fast and automated web reconnaissance and auditing. It features an interactive terminal UI for navigating scans and results.

## Features

- **Interactive TUI** — Navigate menus, select scanners, and browse results with keyboard shortcuts
- **Multi-scanner orchestration** — Run Nmap, Nuclei, ZAP, Feroxbuster, SQLMap, Subfinder, httpx, WPScan, and Hydra from a single interface
- **Parallel execution** — All selected scanners run simultaneously with live status indicators
- **Smart pipelines** — Automated chaining between scanners:
  - **Subfinder → httpx** — Probes discovered subdomains automatically
  - **httpx/Nuclei/Nmap → WPScan** — Runs WPScan if WordPress is detected
  - **ZAP/Nuclei → SQLMap** — Runs SQLMap on endpoints where SQL injection was detected
  - **Nmap → Hydra** — Brute-forces credentials on services discovered by Nmap (SSH, FTP, MySQL, etc.)
- **Auto-installation** — Automatically detects and installs missing tools on Windows, macOS, and Linux
- **Structured findings** — Parsed results with severity levels (Critical, High, Medium, Low, Info)
- **Export** — Save reports as JSON or TXT
- **CLI mode** — Run scans directly from the command line without interactive mode
- **Logging** — Debug logs written to `%LOCALAPPDATA%\octoscan\logs\` (Windows) for troubleshooting

## Prerequisites

OctoScan orchestrates the following security tools:

| Scanner | Install |
|---------|---------|
| [Nmap](https://nmap.org/) | `apt install nmap` / `brew install nmap` / [nmap.org/download](https://nmap.org/download) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [ZAP](https://www.zaproxy.org/) | `apt install zaproxy` / `brew install --cask zap` / [zaproxy.org/download](https://www.zaproxy.org/download/) |
| [Feroxbuster](https://github.com/epi052/feroxbuster) | `apt install feroxbuster` / `brew install feroxbuster` / [GitHub Releases](https://github.com/epi052/feroxbuster/releases) |
| [SQLMap](https://sqlmap.org/) | `apt install sqlmap` / `brew install sqlmap` / `pip install sqlmap` |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | `apt install subfinder` / `brew install subfinder` / [GitHub Releases](https://github.com/projectdiscovery/subfinder/releases) |
| [httpx](https://github.com/projectdiscovery/httpx) | `apt install httpx` / `brew install httpx` / [GitHub Releases](https://github.com/projectdiscovery/httpx/releases) |
| [WPScan](https://wpscan.com/) | `apt install wpscan` / `brew install wpscan` / `gem install wpscan` (requires Ruby) |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra) | `apt install hydra` / `brew install hydra` / [GitHub Releases](https://github.com/maaaaz/thc-hydra-windows/releases) |

> **Note:** On Windows, OctoScan can **automatically install** missing tools when you press `i` on the tool check screen. It handles Npcap, VC++ 2013 runtime, Nmap, Nuclei, ZAP, Feroxbuster, SQLMap, Subfinder, httpx, WPScan (Ruby + DevKit + libcurl), Hydra, and Java 17 dependencies.

## Installation

```bash
# Clone the repository
git clone https://github.com/Coucoudb/OctoScan.git
cd OctoScan

# Build
cargo build --release

# The binary is at target/release/octoscan
```

## Usage

### Interactive mode

```bash
octoscan
```

Launch the TUI and navigate with keyboard shortcuts:

| Key | Action |
|-----|--------|
| `s` | Start a new scan |
| `↑`/`↓` | Navigate / Scroll |
| `Space` | Toggle scanner selection |
| `Enter` | Confirm |
| `Tab` / `Shift+Tab` | Switch between scanner result tabs |
| `e` | Export results |
| `n` | New scan (from results screen) |
| `h` | Toggle help |
| `i` | Install missing tools (from tool check screen) |
| `q` / `Ctrl+C` | Quit |

### CLI mode

```bash
# Scan with specific scanners
octoscan scan -t https://example.com -s nmap,nuclei

# Subdomain enum + HTTP probing
octoscan scan -t example.com -s subfinder,httpx

# WordPress vulnerability scan
octoscan scan -t https://example.com -s wpscan

# Nmap + credential brute-force
octoscan scan -t 192.168.1.1 -s nmap,hydra

# Full scan with all scanners
octoscan scan -t https://example.com -s nmap,nuclei,zap,feroxbuster,sqlmap,hydra -o report.json

# Custom scanner arguments
octoscan scan -t https://example.com -s nmap,nuclei \
  --scanner-args "nmap=--script vuln --top-ports 100" \
  --scanner-args "nuclei=-tags cve -severity critical"
```

### Custom scanner arguments

Use `--scanner-args` to pass extra flags to individual scanners. The format is `scanner=args` and can be repeated:

```bash
--scanner-args "nmap=-sV --script=http-enum"
--scanner-args "nuclei=-tags cve,xss -t /path/to/templates"
--scanner-args "feroxbuster=-w /path/to/wordlist.txt -d 3"
--scanner-args "zap=-quickprogress"
```

Custom arguments are **appended** to the scanner's default flags. Shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, etc.) are rejected to prevent command injection.

In **TUI mode**, a scanner arguments input screen appears after selecting scanners. Enter args in the format `scanner=args, scanner=args` or press Enter to skip.

## Project Structure

```
src/
├── main.rs           # Entry point, CLI dispatch
├── cli.rs            # Clap argument definitions
├── app.rs            # Application state
├── tui.rs            # Terminal event loop
├── ui.rs             # Ratatui UI rendering
├── export.rs         # JSON/TXT export
├── installer.rs      # Auto-installation of missing tools
├── logger.rs         # File-based logging
└── scanners/
    ├── mod.rs        # Scanner trait & types
    ├── nmap.rs       # Nmap integration
    ├── nuclei.rs     # Nuclei integration
    ├── zap.rs        # ZAP integration
    ├── feroxbuster.rs # Feroxbuster integration
    ├── subfinder.rs  # Subfinder subdomain enumeration
    ├── httpx.rs      # httpx HTTP probing & tech detection
    ├── wpscan.rs     # WPScan WordPress vulnerability scanning
    ├── sqlmap.rs     # SQLMap integration (conditional, post-scan)
    └── hydra.rs      # Hydra credential brute-force (conditional, post-Nmap)
```

## CI

GitHub Actions runs on every push/PR to `main`:

- **Lint** — `cargo fmt --check` + `cargo clippy -D warnings`
- **Audit** — `cargo audit` for dependency vulnerabilities
- **SAST** — Semgrep static analysis with SARIF upload
- **Test** — `cargo test` to validate all scanner parsers and edge cases
- **Build** — Release build on Linux, Windows, and macOS

## ⚠️ Legal Disclaimer

Usage of OctoScan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use it on targets you have permission to audit.