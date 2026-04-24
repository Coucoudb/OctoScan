mod app;
mod cli;
mod export;
mod history;
mod installer;
mod logger;
mod profiles;
mod scanners;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let log_path = logger::init();
    let cli = Cli::parse();

    match cli.command {
        Some(cli::Commands::Scan {
            target,
            scanners: scanner_list,
            output,
            scanner_args,
            profile,
        }) => {
            // Resolve scanners from --profile or --scanners
            let selected: Vec<scanners::ScannerType> = if let Some(profile_name) = profile {
                match profiles::find_profile(&profile_name) {
                    Some(p) => p.scanners,
                    None => {
                        let available: Vec<String> = profiles::all_profiles()
                            .iter()
                            .map(|p| p.name.clone())
                            .collect();
                        eprintln!(
                            "Unknown profile: '{}'. Available: {}",
                            profile_name,
                            available.join(", ")
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                scanner_list.iter().filter_map(|s| s.parse().ok()).collect()
            };

            if selected.is_empty() {
                eprintln!("No valid scanners specified. Available: nmap, nuclei, zap");
                std::process::exit(1);
            }

            let parsed_args = match scanners::parse_scanner_args(&scanner_args) {
                Ok(args) => args,
                Err(e) => {
                    eprintln!("Invalid --scanner-args: {}", e);
                    std::process::exit(1);
                }
            };

            let mut app_state = app::App::new(target, selected);
            app_state.log_path = Some(log_path.to_string_lossy().to_string());
            app_state.scanner_args = parsed_args;
            if let Some(out) = output {
                app_state.set_export_path(out);
            }
            tui::run_app(app_state).await?;
        }
        Some(cli::Commands::History { action, diff }) => {
            // `--diff OLD NEW` is a top-level shortcut for `history diff`.
            if let Some(ids) = diff {
                return run_history_diff(&ids[0], &ids[1]);
            }
            match action.unwrap_or(cli::HistoryAction::List) {
                cli::HistoryAction::List => run_history_list()?,
                cli::HistoryAction::Show { id } => run_history_show(&id)?,
                cli::HistoryAction::Export { id, output } => run_history_export(&id, &output)?,
                cli::HistoryAction::Diff { old, new } => run_history_diff(&old, &new)?,
            }
        }
        None => {
            let mut app_state = app::App::new_interactive();
            app_state.log_path = Some(log_path.to_string_lossy().to_string());
            tui::run_app(app_state).await?;
        }
    }

    Ok(())
}

fn run_history_list() -> Result<()> {
    let entries = history::load_all()?;
    if entries.is_empty() {
        println!(
            "No past scans found. History is stored under: {}",
            history::history_dir().display()
        );
        return Ok(());
    }
    println!(
        "{:<10}  {:<20}  {:<25}  {:>4}  SCANNERS",
        "ID", "DATE (UTC)", "TARGET", "FIND"
    );
    println!("{}", "─".repeat(90));
    for e in entries {
        let scanners: Vec<String> = e.scanners.iter().map(|s| s.to_string()).collect();
        println!(
            "{:<10}  {:<20}  {:<25}  {:>4}  {}",
            short_id(&e.id),
            e.started_at.format("%Y-%m-%d %H:%M:%S"),
            truncate(&e.target, 25),
            e.finding_count(),
            scanners.join(", ")
        );
    }
    Ok(())
}

fn run_history_show(id: &str) -> Result<()> {
    let e = history::load_by_id(id)?;
    println!("Scan ID:   {}", e.id);
    println!("Target:    {}", e.target);
    println!(
        "Started:   {}",
        e.started_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Finished:  {}",
        e.finished_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    let scanners: Vec<String> = e.scanners.iter().map(|s| s.to_string()).collect();
    println!("Scanners:  {}", scanners.join(", "));
    let c = &e.severity_counts;
    println!(
        "Findings:  {} (Critical: {}, High: {}, Medium: {}, Low: {}, Info: {})",
        c.total(),
        c.critical,
        c.high,
        c.medium,
        c.low,
        c.info
    );
    println!();
    for r in &e.results {
        println!(
            "── {} ── ({} finding{})",
            r.scanner,
            r.findings.len(),
            if r.findings.len() == 1 { "" } else { "s" }
        );
        for f in &r.findings {
            println!("  [{}] {}", f.severity, f.title);
        }
    }
    Ok(())
}

fn run_history_export(id: &str, output: &str) -> Result<()> {
    let e = history::load_by_id(id)?;
    export::export_scan(&e.id, &e.target, &e.scanners, &e.results, output)?;
    println!("Exported scan {} to {}", short_id(&e.id), output);
    Ok(())
}

fn run_history_diff(old_id: &str, new_id: &str) -> Result<()> {
    let old = history::load_by_id(old_id)?;
    let new = history::load_by_id(new_id)?;
    let report = history::diff(&old, &new);

    println!(
        "Comparing {} ({}) → {} ({})",
        short_id(&old.id),
        old.started_at.format("%Y-%m-%d %H:%M"),
        short_id(&new.id),
        new.started_at.format("%Y-%m-%d %H:%M"),
    );
    println!(
        "Summary: +{} new, -{} fixed, ={} unchanged",
        report.new.len(),
        report.fixed.len(),
        report.unchanged.len()
    );
    println!();

    if !report.new.is_empty() {
        println!("[+] New findings ({}):", report.new.len());
        for (s, f) in &report.new {
            println!("    + [{}] {} — {}", f.severity, s, f.title);
        }
        println!();
    }
    if !report.fixed.is_empty() {
        println!("[-] Fixed findings ({}):", report.fixed.len());
        for (s, f) in &report.fixed {
            println!("    - [{}] {} — {}", f.severity, s, f.title);
        }
        println!();
    }
    if !report.unchanged.is_empty() {
        println!("[=] Unchanged findings: {}", report.unchanged.len());
    }
    Ok(())
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
