use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "octoscan",
    about = "🐙 OctoScan - CLI security auditing tool",
    long_about = "OctoScan orchestrates popular security tools (Nmap, Nuclei, ZAP, Feroxbuster, SQLMap, Subfinder, httpx, WPScan, Hydra) for fast and automated web reconnaissance and auditing.",
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

        /// Scanners to use (nmap, nuclei, zap, feroxbuster, sqlmap, subfinder, httpx, wpscan, hydra)
        #[arg(short, long, value_delimiter = ',')]
        scanners: Vec<String>,

        /// Export results to file (json or txt)
        #[arg(short, long)]
        output: Option<String>,

        /// Custom arguments per scanner, format: "scanner=args" (can be repeated).
        /// Example: --scanner-args "nmap=-sV --script=vuln" --scanner-args "nuclei=-tags cve"
        #[arg(long = "scanner-args", value_name = "SCANNER=ARGS")]
        scanner_args: Vec<String>,

        /// Use a predefined scan profile (quick, web, recon, full) instead of --scanners
        #[arg(short = 'p', long, conflicts_with = "scanners")]
        profile: Option<String>,
    },
}
