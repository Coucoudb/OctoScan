mod app;
mod cli;
mod export;
mod installer;
mod scanners;
mod tui;
mod ui;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(cli::Commands::Scan { target, scanners: scanner_list, output }) => {
            let selected: Vec<scanners::ScannerType> = scanner_list
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();

            if selected.is_empty() {
                eprintln!("No valid scanners specified. Available: nmap, nuclei, zap");
                std::process::exit(1);
            }

            let mut app_state = app::App::new(target, selected);
            if let Some(out) = output {
                app_state.set_export_path(out);
            }
            tui::run_app(app_state).await?;
        }
        None => {
            tui::run_interactive().await?;
        }
    }

    Ok(())
}
