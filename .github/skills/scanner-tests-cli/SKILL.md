---
name: scanner-tests-cli
description: "Generate CLI integration tests for OctoScan scanners and flags. Use when: adding a new scanner CLI flag, writing CLI integration tests, testing argument parsing, testing error messages. Covers binary invocation tests with assert_cmd/predicates, clap unit-level parsing tests, and validation error tests."
---

# Scanner CLI Integration Tests Generator

## When to Use

- Adding a new CLI flag to `src/cli.rs`
- Adding a new scanner and need to verify it's accepted by the CLI
- Testing error messages for invalid input (bad scanner names, missing args, injection)
- Verifying `--help` output includes new flags

## Project Context

- **CLI definition**: `src/cli.rs` (clap v4 derive macros)
- **Test file**: `tests/cli_integration.rs`
- **Dev dependencies**: `assert_cmd = "2"`, `predicates = "3"` (in `Cargo.toml`)
- **Binary name**: `octoscan`

## Two Test Categories

### Category 1 — Binary invocation tests (assert_cmd)

Spawn the actual compiled binary and check exit code + stdout/stderr. Used for end-to-end validation.

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn octoscan() -> Command {
    Command::cargo_bin("octoscan").expect("binary should exist")
}
```

### Category 2 — Clap unit-level parsing tests

Test argument parsing logic without spawning a process. Faster, but requires re-declaring a minimal CLI struct in each test.

## Procedure

### Step 1 — Identify what to test

Read `src/cli.rs` to understand the current flag structure. Determine:
- Is this a **new flag** on the `Scan` subcommand?
- Is this a **new scanner name** to accept?
- Does this flag have **validation logic** in `src/main.rs`?

### Step 2 — Add binary invocation tests

Append tests to `tests/cli_integration.rs` under a section comment. Follow this naming and grouping convention:

```rust
// ─── <feature name> ─────────────────────────────

#[test]
fn <feature>_shown_in_help() {
    octoscan()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--<flag-name>"));
}
```

**Test patterns by scenario:**

#### New flag appears in help
```rust
#[test]
fn <flag>_shown_in_help() {
    octoscan()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--<flag>"));
}
```

#### Invalid format exits with error
```rust
#[test]
fn <flag>_invalid_format_exits_with_error() {
    octoscan()
        .args([
            "scan", "-t", "http://example.com", "-s", "nmap",
            "--<flag>", "<invalid_value>",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("<expected_error_substring>"));
}
```

#### Invalid scanner name rejected
```rust
#[test]
fn <flag>_invalid_scanner_name_exits_with_error() {
    octoscan()
        .args([
            "scan", "-t", "http://example.com", "-s", "nmap",
            "--<flag>", "<scanner_ref>=<value>",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("<expected_error_substring>"));
}
```

#### Shell injection rejected (for flags accepting freeform args)
```rust
#[test]
fn <flag>_shell_injection_rejected() {
    octoscan()
        .args([
            "scan", "-t", "http://example.com", "-s", "nmap",
            "--<flag>", "nmap=-sV; rm -rf /",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("<expected_error_substring>"));
}
```

### Step 3 — Add new scanner name acceptance tests (if adding a scanner)

When adding a new scanner, verify the CLI accepts its name in `-s`:

```rust
#[test]
fn scan_accepts_<tool_name>_scanner() {
    // Won't succeed (tool not installed) but should NOT fail on argument parsing
    octoscan()
        .args(["scan", "-t", "http://example.com", "-s", "<tool_name>"])
        .assert()
        // Don't assert success — the scan will fail because the tool isn't installed
        // Just verify it doesn't fail with "No valid scanners specified"
        .stderr(predicate::str::contains("No valid scanners specified").not());
}
```

Also add the new scanner to the comma-delimited list test:

```rust
#[test]
fn clap_comma_delimited_scanners_parsed_correctly() {
    // ... existing test — add the new scanner name to the list
}
```

### Step 4 — Add clap unit-level tests (if testing parsing logic)

For testing argument parsing without spawning the binary, re-declare a minimal CLI:

```rust
#[test]
fn clap_parses_<scenario>() {
    use clap::Parser;

    #[derive(Parser)]
    #[command(name = "octoscan")]
    struct TestCli {
        #[command(subcommand)]
        command: Option<TestCommands>,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Scan {
            #[arg(short, long)]
            target: String,
            #[arg(short, long, value_delimiter = ',')]
            scanners: Vec<String>,
            #[arg(short, long)]
            output: Option<String>,
            // Add new flags here matching src/cli.rs
        },
    }

    let cli = TestCli::try_parse_from([
        "octoscan", "scan", "-t", "http://example.com", "-s", "nmap",
    ])
    .expect("should parse valid args");

    match cli.command {
        Some(TestCommands::Scan { target, scanners, .. }) => {
            assert_eq!(target, "http://example.com");
            assert_eq!(scanners, vec!["nmap"]);
        }
        None => panic!("expected Scan subcommand"),
    }
}
```

### Step 5 — Verify

```bash
cargo test --test cli_integration
cargo clippy --all-targets -- -D warnings
```

## Existing Test Coverage

Current tests in `tests/cli_integration.rs` cover:

| Category | Tests |
|----------|-------|
| `--help` output | `help_flag_shows_usage`, `scan_help_shows_flags` |
| `--version` | `version_flag` |
| Missing required args | `scan_missing_target_fails`, `scan_missing_scanners_and_target_fails` |
| Invalid scanner names | `scan_all_invalid_scanners_exits_with_error`, `scan_single_invalid_scanner_exits_with_error` |
| Invalid subcommand | `unknown_subcommand_fails` |
| `--scanner-args` | `scanner_args_shown_in_help`, `scanner_args_invalid_format_exits_with_error`, `scanner_args_invalid_scanner_name_exits_with_error`, `scanner_args_shell_injection_rejected` |
| Clap parsing | `clap_parses_valid_scan_args`, `clap_rejects_missing_target`, `clap_comma_delimited_scanners_parsed_correctly`, `clap_no_subcommand_is_interactive_mode` |

Check this table before adding tests to avoid duplicates.

## Common Mistakes

- **Asserting `.success()` on scan commands**: The scan will fail because tools aren't installed in CI. Only assert success for `--help` and `--version`. For scan commands, assert on exit code or stderr content
- **Forgetting `predicate::str::contains`**: Always import `predicates::prelude::*` and use `predicate::str::contains()` for substring matching
- **Hardcoding exit codes**: Use `.code(1)` only when the code explicitly calls `std::process::exit(1)`. For clap errors, just use `.failure()`
- **Not using the `octoscan()` helper**: Always use the shared helper, never `Command::new("octoscan")`
