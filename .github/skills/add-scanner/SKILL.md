---
name: add-scanner
description: "Add a new scanner to OctoScan. Use when: adding a new security tool, integrating a new CLI scanner, creating a scanner module with parser, installer, and TUI registration. Covers all 9 integration points: module creation, enum registration, parser implementation, installer logic, app state, tests, and documentation."
---

# Add a New Scanner to OctoScan

## When to Use

- Integrating a new CLI security tool into OctoScan
- Need guidance on all files that must be modified
- Creating the scanner module, parser, installer, and test fixtures

## Overview

Adding a scanner requires changes in **9 files** across the codebase. This skill walks through each one in order.

## Prerequisites — Know Your Tool

Before starting, gather this information about the tool you're adding:

| Question | Why |
|----------|-----|
| What is the CLI command name? | For `check_tool()` and `get_cmd_name()` |
| What output format does it produce? | Determines parser strategy (text, JSON, JSONL, XML) |
| What CLI flags produce machine-readable output? | For the `Command` construction |
| Does it need the target as URL, host, or IP? | For target preprocessing in `run()` |
| How to install it on Windows / macOS / Linux? | For `installer.rs` |
| What category? (recon, vuln scan, web app, exploit, brute-force) | For `all_scanner_types()` ordering |

## Procedure

### Step 1 — Create the scanner module

Create `src/scanners/<tool_name>.rs`. Use the appropriate template based on the tool's output format.

**Template for text output** (like nmap, subfinder, hydra):

```rust
use anyhow::{Context, Result};
use chrono::Utc;
use std::process::Stdio;
use tokio::process::Command;

use super::{check_tool, Finding, ScanResult, ScannerType, Severity};

pub async fn run(target: &str, extra_args: &[String]) -> Result<ScanResult> {
    let started_at = Utc::now();

    if !check_tool("<cmd_name>").await {
        let finished_at = Utc::now();
        return Ok(ScanResult {
            scanner: ScannerType::<Name>,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: String::new(),
            findings: Vec::new(),
            success: false,
            error: Some("<tool> is not installed or not in PATH".to_string()),
        });
    }

    // Preprocess target if needed (strip protocol, extract host, etc.)
    let host = target;

    let mut cmd = Command::new("<cmd_name>");
    cmd.args([
        // Tool-specific default arguments here
        // Prefer machine-readable output flags (JSON, XML, etc.)
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
        .context("Failed to execute <tool>")?;

    let finished_at = Utc::now();
    let raw_output = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Ok(ScanResult {
            scanner: ScannerType::<Name>,
            target: target.to_string(),
            started_at,
            finished_at,
            raw_output: format!("{}\n{}", raw_output, stderr),
            findings: Vec::new(),
            success: false,
            error: Some(format!("<tool> exited with status: {}", output.status)),
        });
    }

    let findings = parse_<tool_name>_output(&raw_output);

    Ok(ScanResult {
        scanner: ScannerType::<Name>,
        target: target.to_string(),
        started_at,
        finished_at,
        raw_output,
        findings,
        success: true,
        error: None,
    })
}

fn parse_<tool_name>_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // TODO: Parse each line into Finding structs
        // Map tool severity → Severity::{Info, Low, Medium, High, Critical}
        findings.push(Finding {
            title: String::new(),
            severity: Severity::Info,
            description: String::new(),
            details: trimmed.to_string(),
        });
    }

    findings
}
```

**For JSONL output** (like httpx, nuclei, feroxbuster), replace the parse loop with:

```rust
fn parse_<tool_name>_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            // Extract fields from JSON object
            let title = json["field"].as_str().unwrap_or("unknown").to_string();
            findings.push(Finding {
                title,
                severity: Severity::Info,
                description: String::new(),
                details: line.to_string(),
            });
        }
    }

    findings
}
```

**For JSON output** (like wpscan), replace with:

```rust
fn parse_<tool_name>_output(output: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    let json: serde_json::Value = match serde_json::from_str(output) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    // Navigate JSON structure and extract findings
    if let Some(items) = json["results"].as_array() {
        for item in items {
            findings.push(Finding {
                title: item["name"].as_str().unwrap_or("unknown").to_string(),
                severity: Severity::Info,
                description: String::new(),
                details: String::new(),
            });
        }
    }

    findings
}
```

### Step 2 — Register in `src/scanners/mod.rs`

Make **5 additions** (keep alphabetical/consistent order with existing entries):

**a) Module declaration** (top of file):
```rust
pub mod <tool_name>;
```

**b) Enum variant** in `ScannerType`:
```rust
pub enum ScannerType {
    // ... existing variants ...
    <Name>,
}
```

**c) Display impl** arm:
```rust
ScannerType::<Name> => write!(f, "<DisplayName>"),
```

**d) FromStr impl** arm:
```rust
"<tool_name>" => Ok(ScannerType::<Name>),
```

**e) run_scanner() match** arm:
```rust
ScannerType::<Name> => <tool_name>::run(target, extra_args).await,
```

### Step 3 — Update `src/app.rs`

**a) Add to `all_scanner_types()`** under the appropriate category comment:

```rust
pub fn all_scanner_types() -> Vec<ScannerType> {
    vec![
        // Reconnaissance
        ScannerType::Feroxbuster,
        ScannerType::Httpx,
        ScannerType::Nmap,
        ScannerType::Subfinder,
        // Vulnerability Scanning
        ScannerType::Nuclei,
        ScannerType::<Name>,          // ← add here (pick correct category)
        // Web Application
        ScannerType::Wpscan,
        ScannerType::Zap,
        // Exploitation
        ScannerType::Sqlmap,
        // Brute-force
        ScannerType::Hydra,
    ]
}
```

**b) Update `scanner_toggles` array size** — change `[bool; 9]` to `[bool; 10]` in:
- The struct field declaration: `pub scanner_toggles: [bool; N]`
- Both constructors (`new()` and `new_interactive()`): `scanner_toggles: [false; N]`

### Step 4 — Update `src/installer.rs`

Add match arms to these 3 functions:

**a) `get_cmd_name()`** — return the binary name used in PATH:
```rust
ScannerType::<Name> => "<cmd_name>",
```

**b) `get_install_hint()`** — return platform-specific install instructions:
```rust
ScannerType::<Name> => {
    if cfg!(target_os = "windows") {
        "<windows install instruction>".to_string()
    } else if cfg!(target_os = "macos") {
        "brew install <tool>".to_string()
    } else {
        "sudo apt install <tool>".to_string()
    }
}
```

**c) `get_install_method()`** — return the automated install command:
```rust
ScannerType::<Name> => {
    if cfg!(target_os = "windows") {
        // Use PsScript for complex Windows installs, ShellCmd for simple ones
        Some(InstallMethod::ShellCmd("winget install <tool>".to_string()))
    } else if cfg!(target_os = "macos") {
        Some(InstallMethod::ShellCmd("brew install <tool>".to_string()))
    } else {
        Some(InstallMethod::ShellCmd("sudo apt-get install -y <tool>".to_string()))
    }
}
```

If the tool needs a complex Windows installer (download zip, extract, add to PATH), create a dedicated `<tool_name>_ps_script()` function returning a PowerShell script string and use `InstallMethod::PsScript(<tool_name>_ps_script())`.

### Step 5 — Create test fixtures

Create `tests/fixtures/<tool_name>/` with at least 3 files:

| File | Content |
|------|---------|
| `normal.<ext>` | Realistic output with 3+ findings |
| `empty.<ext>` | Valid output with zero findings |
| Edge case file | Malformed input, single result, filtered output, etc. |

Use synthetic data only (`example.com`, `10.0.0.1`, `192.168.1.x`).

Extension matches the tool's output format: `.txt` (text), `.jsonl` (JSON Lines), `.json` (JSON), `.xml` (XML).

### Step 6 — Add unit tests

Add `#[cfg(test)] mod tests` block at the **very end** of `src/scanners/<tool_name>.rs` (must be last item — clippy enforces this).

Minimum 3 tests + empty string test. Use the `/scanner-tests` skill for detailed patterns.

### Step 7 — Add CLI integration tests

Add tests to `tests/cli_integration.rs` to verify the new scanner name is accepted. Use the `/scanner-tests-cli` skill for detailed patterns.

### Step 8 — Update documentation

**a) `README.md`** — Add the tool to the Prerequisites table:
```markdown
| [<Tool>](<homepage>) | `apt install <tool>` / `brew install <tool>` / [download](<url>) |
```

**b) `src/cli.rs`** — Add tool name to the `--scanners` help text:
```rust
/// Scanners to use (nmap, nuclei, zap, feroxbuster, sqlmap, subfinder, httpx, wpscan, hydra, <tool_name>)
```

### Step 9 — Verify

Run all checks:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

All must pass with zero warnings.

## Checklist

```
[ ] src/scanners/<tool_name>.rs created with run() + parse_*_output()
[ ] src/scanners/mod.rs — pub mod, enum variant, Display, FromStr, run_scanner()
[ ] src/app.rs — all_scanner_types() + scanner_toggles array size
[ ] src/installer.rs — get_cmd_name() + get_install_hint() + get_install_method()
[ ] tests/fixtures/<tool_name>/ — 3+ fixture files
[ ] src/scanners/<tool_name>.rs — #[cfg(test)] mod tests with 3+ tests
[ ] tests/cli_integration.rs — scanner name acceptance test
[ ] README.md — Prerequisites table updated
[ ] src/cli.rs — --scanners help text updated
[ ] cargo fmt + clippy + test + build all pass
```

## Common Mistakes

- **Forgetting `Hash` derive**: `ScannerType` derives `Hash` — new variants get it automatically, but if you add a field to an inner struct, ensure it implements `Hash`
- **Wrong array size**: `scanner_toggles: [bool; N]` must match the total count of scanners in `all_scanner_types()`. Update in 3 places (field + 2 constructors)
- **Test module not last**: Clippy's `items_after_test_module` lint rejects code after `#[cfg(test)]` blocks
- **Missing `extra_args` support**: The `run()` function must accept `extra_args: &[String]` and append them to the command with `cmd.args(extra_args)`
- **Not handling tool-not-installed**: Always check `check_tool("<cmd>").await` first and return a graceful error
