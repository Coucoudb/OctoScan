use assert_cmd::Command;
use predicates::prelude::*;

/// Helper to build a Command for the octoscan binary.
fn octoscan() -> Command {
    Command::cargo_bin("octoscan").expect("binary should exist")
}

// ─── --help output ──────────────────────────────

#[test]
fn help_flag_shows_usage() {
    octoscan()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("OctoScan"))
        .stdout(predicate::str::contains("scan"));
}

#[test]
fn scan_help_shows_flags() {
    octoscan()
        .args(["scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--target"))
        .stdout(predicate::str::contains("--scanners"))
        .stdout(predicate::str::contains("--output"));
}

#[test]
fn version_flag() {
    octoscan()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("octoscan"));
}

// ─── Missing required args ──────────────────────

#[test]
fn scan_missing_target_fails() {
    octoscan()
        .args(["scan", "-s", "nmap"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--target"));
}

#[test]
fn scan_missing_scanners_and_target_fails() {
    octoscan()
        .arg("scan")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--target"));
}

// ─── Invalid scanner names ──────────────────────

#[test]
fn scan_all_invalid_scanners_exits_with_error() {
    octoscan()
        .args(["scan", "-t", "http://example.com", "-s", "notreal,fake"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("No valid scanners specified"));
}

#[test]
fn scan_single_invalid_scanner_exits_with_error() {
    octoscan()
        .args(["scan", "-t", "http://example.com", "-s", "doesnotexist"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("No valid scanners specified"));
}

// ─── Invalid subcommand ─────────────────────────

#[test]
fn unknown_subcommand_fails() {
    octoscan()
        .arg("foobar")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand"));
}

// ─── Argument parsing via clap (unit-level, no binary spawn) ───

#[test]
fn clap_parses_valid_scan_args() {
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
        },
    }

    // Valid: -t + -s + -o json
    let cli = TestCli::try_parse_from([
        "octoscan",
        "scan",
        "-t",
        "http://example.com",
        "-s",
        "nmap,nuclei",
        "-o",
        "report.json",
    ])
    .expect("should parse valid args");

    match cli.command {
        Some(TestCommands::Scan {
            target,
            scanners,
            output,
        }) => {
            assert_eq!(target, "http://example.com");
            assert_eq!(scanners, vec!["nmap", "nuclei"]);
            assert_eq!(output.as_deref(), Some("report.json"));
        }
        None => panic!("expected Scan subcommand"),
    }

    // Valid: -t + -s + -o txt
    let cli2 = TestCli::try_parse_from([
        "octoscan",
        "scan",
        "-t",
        "https://test.com",
        "-s",
        "zap",
        "-o",
        "results.txt",
    ])
    .expect("should parse valid args");

    match cli2.command {
        Some(TestCommands::Scan {
            target,
            scanners,
            output,
        }) => {
            assert_eq!(target, "https://test.com");
            assert_eq!(scanners, vec!["zap"]);
            assert_eq!(output.as_deref(), Some("results.txt"));
        }
        None => panic!("expected Scan subcommand"),
    }

    // Valid: -t + -s without -o
    let cli3 = TestCli::try_parse_from([
        "octoscan",
        "scan",
        "-t",
        "192.168.1.1",
        "-s",
        "nmap,feroxbuster,httpx",
    ])
    .expect("should parse valid args");

    match cli3.command {
        Some(TestCommands::Scan {
            target,
            scanners,
            output,
        }) => {
            assert_eq!(target, "192.168.1.1");
            assert_eq!(scanners, vec!["nmap", "feroxbuster", "httpx"]);
            assert!(output.is_none());
        }
        None => panic!("expected Scan subcommand"),
    }
}

#[test]
fn clap_rejects_missing_target() {
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
        },
    }

    let result = TestCli::try_parse_from(["octoscan", "scan", "-s", "nmap"]);
    assert!(result.is_err());
}

#[test]
fn clap_comma_delimited_scanners_parsed_correctly() {
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
        },
    }

    let cli = TestCli::try_parse_from([
        "octoscan",
        "scan",
        "-t",
        "http://example.com",
        "-s",
        "nmap,nuclei,zap,feroxbuster,sqlmap,subfinder,httpx,wpscan,hydra",
    ])
    .expect("should parse all scanners");

    match cli.command {
        Some(TestCommands::Scan { scanners, .. }) => {
            assert_eq!(scanners.len(), 9);
            assert_eq!(
                scanners,
                vec![
                    "nmap",
                    "nuclei",
                    "zap",
                    "feroxbuster",
                    "sqlmap",
                    "subfinder",
                    "httpx",
                    "wpscan",
                    "hydra"
                ]
            );
        }
        None => panic!("expected Scan subcommand"),
    }
}

#[test]
fn clap_no_subcommand_is_interactive_mode() {
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
        },
    }

    let cli = TestCli::try_parse_from(["octoscan"]).expect("no subcommand should be valid");
    assert!(cli.command.is_none());
}
