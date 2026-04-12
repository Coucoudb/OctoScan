---
name: scanner-tests
description: "Generate unit tests for OctoScan scanner parsers. Use when: adding a new scanner, writing scanner tests, creating test fixtures, testing parse functions. Covers fixture creation, test module scaffolding, and assertion patterns for all scanner output formats (JSONL, JSON, XML, plain text)."
---

# Scanner Unit Tests Generator

## When to Use

- Adding a new scanner module to `src/scanners/`
- Writing or updating parser unit tests for an existing scanner
- Creating test fixture files for scanner output

## Project Context

- **Scanner modules**: `src/scanners/<tool_name>.rs`
- **Fixture directory**: `tests/fixtures/<tool_name>/`
- **Types**: `ScannerType`, `Finding`, `Severity`, `ScanResult` from `src/scanners/mod.rs`
- **Minimum tests required**: 3 per scanner (normal output, empty output, edge case)

## Severity Enum

```rust
pub enum Severity { Info, Low, Medium, High, Critical }
```

## Finding Struct

```rust
pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub details: String,
}
```

## Procedure

### Step 1 — Identify the parser function

Read the scanner module at `src/scanners/<tool_name>.rs`. Locate the **private parse function**:

```rust
fn parse_<tool_name>_output(output: &str) -> Vec<Finding>
```

Understand what output format it expects (JSONL, JSON, XML, plain text) and what `Finding` fields it produces.

### Step 2 — Create fixture files

Create **at least 3** fixture files in `tests/fixtures/<tool_name>/`:

| File | Purpose | Content |
|------|---------|---------|
| `normal.<ext>` | Typical output with multiple findings | Representative real tool output |
| `empty.<ext>` | No results / empty scan | Minimal valid output or empty string |
| Edge case file | Malformed, filtered, single item, or variant output | Depends on parser logic |

**Extension conventions by output format:**

| Format | Extension | Scanners using it |
|--------|-----------|------------------|
| JSON Lines | `.jsonl` | httpx, feroxbuster, nuclei |
| JSON | `.json` | wpscan, zap (alerts) |
| XML | `.xml` | zap |
| Plain text | `.txt` | nmap, subfinder, sqlmap, hydra |

**Fixture rules:**
- Use realistic but **synthetic** data (no real IPs/domains — use `example.com`, `10.0.0.1`, `192.168.1.x`)
- Include enough entries to validate counting (3+ findings for normal output)
- Edge case fixtures should exercise specific parser branches (filtering, error handling, special formats)

### Step 3 — Write the test module

Add a `#[cfg(test)] mod tests` block **at the very end** of the scanner file (after all functions — clippy enforces this via `items_after_test_module`).

**Required test functions:**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_output() {
        let input = include_str!("../../tests/fixtures/<tool_name>/normal.<ext>");
        let findings = parse_<tool_name>_output(input);
        assert_eq!(findings.len(), <expected_count>);
        // Assert on first finding's fields
        assert!(findings[0].title.contains("<expected_substring>"));
        assert!(matches!(findings[0].severity, Severity::<Variant>));
    }

    #[test]
    fn parse_empty_output() {
        let input = include_str!("../../tests/fixtures/<tool_name>/empty.<ext>");
        let findings = parse_<tool_name>_output(input);
        assert!(findings.is_empty());
    }

    #[test]
    fn parse_<edge_case_name>() {
        let input = include_str!("../../tests/fixtures/<tool_name>/<edge_case>.<ext>");
        let findings = parse_<tool_name>_output(input);
        // Assertions specific to the edge case
    }

    #[test]
    fn parse_completely_empty_string() {
        let findings = parse_<tool_name>_output("");
        assert!(findings.is_empty());
    }
}
```

**Key patterns:**
- Always use `include_str!("../../tests/fixtures/...")` — path is relative to the scanner `.rs` file
- Use `matches!()` macro for `Severity` enum assertions
- Filter findings by type when testing mixed output: `findings.iter().filter(|f| f.title.starts_with("Open port")).collect()`
- For helper/utility functions (e.g. `is_static_asset`, `extract_xml_tag`), add dedicated tests alongside the parser tests

### Step 4 — Register in mod.rs (if new scanner)

If this is a **new** scanner, also update `src/scanners/mod.rs`:
- Add variant to `ScannerType` enum
- Add `pub mod <tool_name>;`
- Add match arm in `run_scanner()`

### Step 5 — Verify

Run:

```bash
cargo test --lib scanners::<tool_name>
cargo clippy --all-targets -- -D warnings
```

All tests must pass and clippy must be clean.

## Common Mistakes

- **Test module not last**: `#[cfg(test)] mod tests` must be the LAST item in the file or clippy rejects it
- **Wrong include_str path**: Path is `../../tests/fixtures/` from `src/scanners/` (two levels up)
- **Testing `run()` instead of `parse_*()`**: Unit tests target the **parse function only** — `run()` requires the external tool installed
- **Forgetting `parse_completely_empty_string`**: Always test with `""` directly (no fixture file needed)
