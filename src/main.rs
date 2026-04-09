mod app;
mod cli;
mod export;
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
        None => {
            let mut app_state = app::App::new_interactive();
            app_state.log_path = Some(log_path.to_string_lossy().to_string());
            tui::run_app(app_state).await?;
        }
    }

    Ok(())
}
