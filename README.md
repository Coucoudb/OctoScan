# 🐙 OctoScan

OctoScan is a CLI wrapper that orchestrates popular security tools (Nmap, Nuclei, ZAP, ...) for fast and automated web reconnaissance and auditing. It features an interactive terminal UI for navigating scans and results.

## Features

- **Interactive TUI** — Navigate menus, select scanners, and browse results with keyboard shortcuts
- **Multi-scanner orchestration** — Run Nmap, Nuclei, and ZAP from a single interface
- **Structured findings** — Parsed results with severity levels (Critical, High, Medium, Low, Info)
- **Export** — Save reports as JSON or TXT
- **CLI mode** — Run scans directly from the command line without interactive mode

## Prerequisites

Install the security tools you want to use:

| Scanner | Install |
|---------|---------|
| [Nmap](https://nmap.org/) | `apt install nmap` / `brew install nmap` / [nmap.org/download](https://nmap.org/download) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [ZAP](https://www.zaproxy.org/) | `apt install zaproxy` / `brew install --cask zap` / [zaproxy.org/download](https://www.zaproxy.org/download/) |

OctoScan will detect which tools are available and report if any are missing.

## Installation

```bash
# Clone the repository
git clone https://github.com/your-user/octoscan.git
cd octoscan

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
| `?` | Toggle help |
| `q` / `Ctrl+C` | Quit |

### CLI mode

```bash
# Scan with specific scanners
octoscan scan -t https://example.com -s nmap,nuclei

# Scan and export to JSON
octoscan scan -t https://example.com -s nmap,nuclei,zap -o report.json

# Scan and export to TXT
octoscan scan -t 192.168.1.1 -s nmap -o report.txt
```

## Project Structure

```
src/
├── main.rs           # Entry point, CLI dispatch
├── cli.rs            # Clap argument definitions
├── app.rs            # Application state
├── tui.rs            # Terminal event loop
├── ui.rs             # Ratatui UI rendering
├── export.rs         # JSON/TXT export
└── scanners/
    ├── mod.rs        # Scanner trait & types
    ├── nmap.rs       # Nmap integration
    ├── nuclei.rs     # Nuclei integration
    └── zap.rs        # ZAP integration
```

## ⚠️ Legal Disclaimer

Usage of OctoScan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use it on targets you have permission to audit.