# Contributing to OctoScan

Thank you for your interest in contributing to OctoScan! This document describes how to build the project, the conventions we follow, and how to submit changes.

## Table of Contents

- [Building the Project](#building-the-project)
- [Pre-commit Hooks](#pre-commit-hooks)
- [Naming Conventions](#naming-conventions)
- [Branching Strategy](#branching-strategy)
- [CI Pipeline](#ci-pipeline)
- [Changelog](#changelog)
- [Submitting a Merge Request](#submitting-a-merge-request)
- [Adding a New Scanner](#adding-a-new-scanner)

---

## Building the Project

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (edition 2021, stable toolchain)
- `cargo` (ships with Rust)

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run directly
cargo run

# Run in CLI mode
cargo run -- scan -t https://example.com -s nmap,nuclei
```

### Useful Development Commands

```bash
# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Audit dependencies for vulnerabilities
cargo install cargo-audit   # one-time install
cargo audit

# Run tests
cargo test
```

> **Tip:** Always run `cargo fmt` and `cargo clippy -- -D warnings` locally before pushing. The CI pipeline will reject code that fails either check.

---

## Pre-commit Hooks

The repository includes a Git hook that automatically runs `cargo fmt --check` and `cargo clippy -- -D warnings` before every commit, so formatting and lint issues are caught locally before reaching CI.

### Setup (one-time)

```bash
git config core.hooksPath .githooks
```

This tells Git to use the hooks in `.githooks/` instead of the default `.git/hooks/`. The pre-commit hook will now run automatically on every `git commit`.

### What it checks

1. **`cargo fmt -- --check`** — Rejects the commit if code is not formatted. Run `cargo fmt` to fix.
2. **`cargo clippy --all-targets -- -D warnings`** — Rejects the commit if Clippy reports any warnings.

### Skipping the hook (emergency only)

```bash
git commit --no-verify -m "fix: urgent hotfix"
```

> Only skip hooks when absolutely necessary. CI will still enforce the same checks.

---

## Naming Conventions

### Rust Code

| Element           | Convention       | Example                          |
|-------------------|------------------|----------------------------------|
| Crate / Package   | `snake_case`     | `octoscan`                       |
| Modules / Files   | `snake_case`     | `feroxbuster.rs`, `mod.rs`       |
| Functions         | `snake_case`     | `run_scanner()`, `check_tool()`  |
| Variables         | `snake_case`     | `scan_result`, `tool_name`       |
| Structs / Enums   | `PascalCase`     | `ScanResult`, `ScannerType`      |
| Enum Variants     | `PascalCase`     | `ScannerType::Feroxbuster`       |
| Constants         | `SCREAMING_SNAKE` | `MAX_RETRIES`                   |
| Type Parameters   | Single uppercase | `T`, `E`                         |
| Trait names       | `PascalCase`     | `Scanner`                        |

### Git

| Element         | Convention                                           | Example                                  |
|-----------------|------------------------------------------------------|------------------------------------------|
| Branch name     | `type/short-description` (kebab-case)                | `feat/add-nikto-scanner`                 |
| Commit message  | `type(scope): description` ([Conventional Commits](https://www.conventionalcommits.org/)) | `feat(scanners): add Nikto integration`  |

#### Commit Types

| Type       | Purpose                                      |
|------------|----------------------------------------------|
| `feat`     | New feature                                  |
| `fix`      | Bug fix                                      |
| `docs`     | Documentation changes only                   |
| `style`    | Formatting, no code logic change             |
| `refactor` | Code restructuring, no feature/fix           |
| `test`     | Adding or updating tests                     |
| `ci`       | CI/CD pipeline changes                       |
| `chore`    | Maintenance tasks (dependencies, tooling)    |

---

## Branching Strategy

```
main ← dev ← feature / fix branches
```

| Branch              | Purpose                                                                 |
|---------------------|-------------------------------------------------------------------------|
| `main`              | Production-ready code. Protected — no direct push allowed.              |
| `dev`           | Integration branch. All feature/fix branches merge here first.          |
| `feat/<name>`       | New feature development. Branch off `dev`.                          |
| `fix/<name>`        | Bug fixes. Branch off `dev`.                                        |
| `docs/<name>`       | Documentation-only changes.                                             |
| `ci/<name>`         | CI/CD configuration changes.                                            |
| `refactor/<name>`   | Code refactoring without behavior changes.                              |

### Workflow

1. **Create a branch** from `dev`:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feat/add-nikto-scanner
   ```
2. **Make small, focused commits** following the commit message convention.
3. **Push** and open a Merge Request targeting `dev`.
4. Once `dev` is stable and tested, a maintainer merges `dev` → `main`.

---

## CI Pipeline

GitHub Actions runs automatically on every push and pull request to `main` and `dev`. All checks must pass before a merge request can be merged.

| Stage     | Tool              | Purpose                                        |
|-----------|-------------------|-------------------------------------------------|
| **Lint**  | `cargo fmt`       | Ensures consistent code formatting              |
| **Lint**  | `cargo clippy`    | Catches common mistakes and enforces idioms     |
| **Audit** | `cargo audit`     | Detects known vulnerabilities in dependencies   |
| **SAST**  | Semgrep           | Static analysis for security issues (SARIF)     |
| **Test**  | `cargo test`      | Validates all scanner parsers and edge cases     |
| **Build** | `cargo build`     | Release build on Linux, Windows, and macOS      |
| **Changelog** | `git-cliff`   | Auto-generates release notes from Conventional Commits |

> A failing pipeline blocks the merge. Fix all issues before requesting review.

---

## Changelog

The project uses [git-cliff](https://git-cliff.org/) to auto-generate `CHANGELOG.md` from Conventional Commits. The configuration lives in `cliff.toml`.

### How it works

- On every push to `main`, the CI release job runs `git-cliff --latest` to generate the release notes for the GitHub Release.
- The full `CHANGELOG.md` is maintained in the repository and can be regenerated locally.

### Regenerate locally

```bash
# Install git-cliff (one-time)
cargo install git-cliff

# Regenerate the full changelog
git-cliff --output CHANGELOG.md

# Preview the changelog for the next (unreleased) version
git-cliff --unreleased
```

> **Important:** Because the changelog is generated from commit messages, following the [Conventional Commits](https://www.conventionalcommits.org/) format is essential. Non-conforming commits are excluded from the changelog.

---

## Submitting a Merge Request

### Before You Submit

- [ ] Code compiles without errors (`cargo build`)
- [ ] No formatting issues (`cargo fmt --check`)
- [ ] No Clippy warnings (`cargo clippy -- -D warnings`)
- [ ] No known dependency vulnerabilities (`cargo audit`)
- [ ] Relevant tests pass (`cargo test`)
- [ ] Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/) format
- [ ] Branch is up to date with `dev` (rebase if needed)

### Merge Request Process

1. **Open a MR** targeting `dev` with a clear title following the commit convention (e.g., `feat(scanners): add Nikto integration`).
2. **Fill in the description**:
   - What the change does and why
   - How to test it
   - Any breaking changes or dependencies added
3. **Request a review** from at least one maintainer.
4. **Address review feedback** — push fixup commits, then squash before final merge if requested.
5. **CI must be green** — all pipeline stages must pass.
6. **A maintainer approves and merges** — do not merge your own MR unless explicitly authorized.

### Review Criteria

Reviewers will check for:

- **Correctness** — Does the code do what it claims?
- **Security** — No credentials, no unsafe input handling, no new vulnerabilities.
- **Style** — Follows naming conventions and idiomatic Rust patterns.
- **Scope** — MR addresses a single concern; no unrelated changes bundled in.
- **Cross-platform** — Changes work on Windows, macOS, and Linux (use `cfg!(target_os)` where needed).

---

## Adding a New Scanner

If you want to add a new security tool, follow the existing scanner module pattern:

1. Create `src/scanners/<tool_name>.rs` with an async `run(target: &str) -> Result<ScanResult>` function.
2. Implement tool availability check via `check_tool()`.
3. Parse tool output into `Finding` structs with appropriate `Severity` levels.
4. Add a `#[cfg(test)]` module with at least 3 tests for the parser (normal output, empty output, edge case). Place sample tool output files in `tests/fixtures/<tool_name>/`.
5. Register the scanner in `src/scanners/mod.rs` by adding a variant to `ScannerType` and updating `run_scanner()`.
6. Add installation logic in `src/installer.rs` for all three platforms (Windows, macOS, Linux).
7. Update `README.md` with the new tool in the prerequisites table.

---

## Questions?

Open an issue on [GitHub](https://github.com/Coucoudb/OctoScan/issues) if you have questions or need guidance before starting work.
