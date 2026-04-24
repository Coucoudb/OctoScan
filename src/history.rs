//! Scan history storage and diff utilities.
//!
//! History entries are persisted as JSON files under the user's local data
//! directory (e.g. `~/.local/share/octoscan/history/` on Linux,
//! `%LOCALAPPDATA%\octoscan\history\` on Windows). Each scan produces a
//! single `<scan_id>.json` file that contains the full results plus a
//! summary header (target, dates, scanners, severity counts).

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::app::App;
use crate::scanners::{Finding, ScanResult, ScannerType, Severity};

/// Severity counts for a scan, used in summaries and diffs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn from_results(results: &[ScanResult]) -> Self {
        let mut c = Self::default();
        for r in results {
            for f in &r.findings {
                match f.severity {
                    Severity::Critical => c.critical += 1,
                    Severity::High => c.high += 1,
                    Severity::Medium => c.medium += 1,
                    Severity::Low => c.low += 1,
                    Severity::Info => c.info += 1,
                }
            }
        }
        c
    }

    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.info
    }
}

/// A single persisted scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: String,
    pub target: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub scanners: Vec<ScannerType>,
    pub severity_counts: SeverityCounts,
    pub results: Vec<ScanResult>,
}

impl HistoryEntry {
    pub fn finding_count(&self) -> usize {
        self.severity_counts.total()
    }
}

/// Resolve the directory used to store history files.
/// Falls back to `./.octoscan/history` when no data dir is available.
pub fn history_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("octoscan").join("history")
}

fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create history directory: {}", dir.display()))
}

/// Persist a completed scan to the history directory.
/// Returns the path to the written JSON file.
pub fn save_scan(app: &App) -> Result<PathBuf> {
    save_scan_to(app, &history_dir())
}

/// Variant of `save_scan` allowing a custom directory (used by tests).
pub fn save_scan_to(app: &App, dir: &Path) -> Result<PathBuf> {
    ensure_dir(dir)?;

    let entry = HistoryEntry {
        id: app.id.to_string(),
        target: app.target.clone(),
        started_at: app.started_at.unwrap_or_else(Utc::now),
        finished_at: app.finished_at.unwrap_or_else(Utc::now),
        scanners: app.selected_scanners.clone(),
        severity_counts: SeverityCounts::from_results(&app.results),
        results: app.results.clone(),
    };

    let path = dir.join(format!("{}.json", entry.id));
    let json = serde_json::to_string_pretty(&entry).context("Failed to serialize history entry")?;
    fs::write(&path, json)
        .with_context(|| format!("Failed to write history entry to {}", path.display()))?;
    Ok(path)
}

/// Load all history entries from the default directory, sorted by
/// `started_at` descending (newest first).
pub fn load_all() -> Result<Vec<HistoryEntry>> {
    load_all_from(&history_dir())
}

/// Variant of `load_all` allowing a custom directory.
pub fn load_all_from(dir: &Path) -> Result<Vec<HistoryEntry>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<HistoryEntry> = Vec::new();
    for dir_entry in fs::read_dir(dir)
        .with_context(|| format!("Failed to read history directory: {}", dir.display()))?
    {
        let dir_entry = dir_entry?;
        let path = dir_entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        match load_file(&path) {
            Ok(e) => entries.push(e),
            Err(err) => {
                log::warn!("Skipping invalid history file {}: {}", path.display(), err);
            }
        }
    }
    entries.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    Ok(entries)
}

/// Load a single history entry by its scan id (uuid string). Accepts a
/// short prefix as long as it uniquely matches one entry.
pub fn load_by_id(id: &str) -> Result<HistoryEntry> {
    load_by_id_from(id, &history_dir())
}

pub fn load_by_id_from(id: &str, dir: &Path) -> Result<HistoryEntry> {
    let exact = dir.join(format!("{}.json", id));
    if exact.exists() {
        return load_file(&exact);
    }
    // Allow short-prefix matching for convenience.
    let mut matches: Vec<PathBuf> = Vec::new();
    if dir.exists() {
        for dir_entry in fs::read_dir(dir)? {
            let path = dir_entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem.starts_with(id) {
                    matches.push(path);
                }
            }
        }
    }
    match matches.len() {
        0 => anyhow::bail!("No history entry matches id '{}'", id),
        1 => load_file(&matches[0]),
        n => anyhow::bail!("Ambiguous id '{}' matches {} entries", id, n),
    }
}

fn load_file(path: &Path) -> Result<HistoryEntry> {
    let text =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let entry: HistoryEntry = serde_json::from_str(&text)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(entry)
}

/// Result of comparing two scans.
#[derive(Debug, Clone, Default)]
pub struct DiffReport {
    pub new: Vec<(ScannerType, Finding)>,
    pub fixed: Vec<(ScannerType, Finding)>,
    pub unchanged: Vec<(ScannerType, Finding)>,
}

/// Build a stable fingerprint for a finding so it can be matched across scans.
fn finding_key(scanner: &ScannerType, f: &Finding) -> String {
    format!("{}|{}|{}|{}", scanner, f.severity, f.title, f.details)
}

/// Compute a side-by-side diff between two scans. Findings are matched by a
/// fingerprint of (scanner, severity, title, details).
pub fn diff(old: &HistoryEntry, new: &HistoryEntry) -> DiffReport {
    let mut old_map: HashMap<String, (ScannerType, Finding)> = HashMap::new();
    for r in &old.results {
        for f in &r.findings {
            old_map.insert(finding_key(&r.scanner, f), (r.scanner.clone(), f.clone()));
        }
    }

    let mut report = DiffReport::default();
    for r in &new.results {
        for f in &r.findings {
            let key = finding_key(&r.scanner, f);
            if old_map.remove(&key).is_some() {
                report.unchanged.push((r.scanner.clone(), f.clone()));
            } else {
                report.new.push((r.scanner.clone(), f.clone()));
            }
        }
    }
    // Anything left in old_map was present before but is gone now.
    report.fixed.extend(old_map.into_values());
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn finding(title: &str, sev: Severity) -> Finding {
        Finding {
            title: title.to_string(),
            severity: sev,
            description: String::new(),
            details: String::new(),
        }
    }

    fn entry(id: &str, target: &str, findings: Vec<(ScannerType, Finding)>) -> HistoryEntry {
        let mut by_scanner: HashMap<ScannerType, Vec<Finding>> = HashMap::new();
        for (s, f) in findings {
            by_scanner.entry(s).or_default().push(f);
        }
        let results: Vec<ScanResult> = by_scanner
            .into_iter()
            .map(|(scanner, findings)| ScanResult {
                scanner,
                target: target.to_string(),
                started_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                finished_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
                raw_output: String::new(),
                findings,
                success: true,
                error: None,
            })
            .collect();

        HistoryEntry {
            id: id.to_string(),
            target: target.to_string(),
            started_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            finished_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 1, 0).unwrap(),
            scanners: vec![ScannerType::Nmap],
            severity_counts: SeverityCounts::from_results(&results),
            results,
        }
    }

    #[test]
    fn severity_counts_aggregates_all_findings() {
        let results = vec![ScanResult {
            scanner: ScannerType::Nmap,
            target: "x".into(),
            started_at: Utc::now(),
            finished_at: Utc::now(),
            raw_output: String::new(),
            findings: vec![
                finding("a", Severity::Critical),
                finding("b", Severity::High),
                finding("c", Severity::High),
                finding("d", Severity::Info),
            ],
            success: true,
            error: None,
        }];
        let c = SeverityCounts::from_results(&results);
        assert_eq!(c.critical, 1);
        assert_eq!(c.high, 2);
        assert_eq!(c.info, 1);
        assert_eq!(c.total(), 4);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempdir().unwrap();
        let e = entry(
            "11111111-1111-1111-1111-111111111111",
            "example.com",
            vec![(ScannerType::Nmap, finding("port 22 open", Severity::Info))],
        );
        let path = dir.path().join(format!("{}.json", e.id));
        fs::write(&path, serde_json::to_string(&e).unwrap()).unwrap();

        let loaded = load_all_from(dir.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, e.id);
        assert_eq!(loaded[0].finding_count(), 1);
    }

    #[test]
    fn load_by_id_supports_prefix() {
        let dir = tempdir().unwrap();
        let e = entry(
            "deadbeef-0000-0000-0000-000000000000",
            "x",
            vec![(ScannerType::Nmap, finding("a", Severity::Low))],
        );
        let path = dir.path().join(format!("{}.json", e.id));
        fs::write(&path, serde_json::to_string(&e).unwrap()).unwrap();

        let loaded = load_by_id_from("deadbeef", dir.path()).unwrap();
        assert_eq!(loaded.id, e.id);
    }

    #[test]
    fn diff_classifies_new_fixed_unchanged() {
        let old = entry(
            "a",
            "t",
            vec![
                (ScannerType::Nmap, finding("port 22", Severity::Info)),
                (ScannerType::Nmap, finding("port 80", Severity::Info)),
                (ScannerType::Nuclei, finding("CVE-1", Severity::High)),
            ],
        );
        let new = entry(
            "b",
            "t",
            vec![
                (ScannerType::Nmap, finding("port 22", Severity::Info)), // unchanged
                (ScannerType::Nmap, finding("port 443", Severity::Info)), // new
                (ScannerType::Nuclei, finding("CVE-2", Severity::High)), // new
                                                                         // CVE-1 and port 80 are fixed
            ],
        );
        let report = diff(&old, &new);
        assert_eq!(report.unchanged.len(), 1);
        assert_eq!(report.new.len(), 2);
        assert_eq!(report.fixed.len(), 2);
    }
}
