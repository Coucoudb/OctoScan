use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "octoscan",
    about = "🐙 OctoScan - CLI security auditing tool",
    long_about = "OctoScan orchestrates popular security tools (Nmap, Nuclei, ZAP, Feroxbuster, SQLMap) for fast and automated web reconnaissance and auditing.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Launch a scan against a target
    Scan {
        /// Target URL or IP address
        #[arg(short, long)]
        target: String,

        /// Scanners to use (nmap, nuclei, zap, feroxbuster, sqlmap)
        #[arg(short, long, value_delimiter = ',')]
        scanners: Vec<String>,

        /// Export results to file (json or txt)
        #[arg(short, long)]
        output: Option<String>,
    },
}
