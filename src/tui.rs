use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app::{App, AppScreen, ScanStatus, ScannerRunStatus};
use crate::installer::{self, InstallStatus};
use crate::scanners;
use crate::ui;

enum AppEvent {
    // Scan events
    ScannerStarted(scanners::ScannerType),
    ScanResult(scanners::ScanResult),
    ScanDone,
    // Chained scan events (smart pipelines)
    HttpxChainResult(scanners::ScanResult),
    HttpxChainDone,
    WpscanChainResult(scanners::ScanResult),
    WpscanChainDone,
    // SQLMap post-scan
    SqlmapResult(scanners::ScanResult),
    SqlmapDone,
    // Hydra post-scan
    HydraResult(scanners::ScanResult),
    HydraDone,
    // Tool check events
    ToolCheckDone(Vec<installer::ToolStatus>),
    // Install events
    InstallProgress(installer::InstallProgress),
    InstallDone,
}

pub async fn run_app(mut app: App) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_event_loop(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let mut event_rx: Option<mpsc::Receiver<AppEvent>> = None;

    // If we started in Scanning mode (from CLI), check tools first
    if app.screen == AppScreen::Scanning && app.scan_status == ScanStatus::Idle {
        app.screen = AppScreen::ToolCheck;
        app.progress_message = "Checking installed tools...".to_string();
        event_rx = Some(start_tool_check(app.selected_scanners.clone()));
    }

    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        // Process async events
        if let Some(ref mut rx) = event_rx {
            while let Ok(event) = rx.try_recv() {
                match event {
                    AppEvent::ToolCheckDone(statuses) => {
                        app.tool_statuses = statuses;
                        app.progress_message.clear();

                        if app.all_tools_installed() {
                            // All good, start scanning
                            app.scan_status = ScanStatus::Running;
                            app.started_at = Some(chrono::Utc::now());
                            app.screen = AppScreen::Scanning;
                            app.init_scanner_statuses();
                            event_rx =
                                Some(start_scan_task(app.target.clone(), app.parallel_scanners()));
                        } else {
                            // Some tools missing, show install prompt
                            app.screen = AppScreen::ToolCheck;
                            event_rx = None;
                        }
                        break;
                    }
                    AppEvent::InstallProgress(progress) => {
                        app.install_progress.push(progress);
                    }
                    AppEvent::InstallDone => {
                        // Refresh PATH in current process to pick up new installs
                        installer::refresh_path();

                        let any_failed = app
                            .install_progress
                            .iter()
                            .any(|p| p.status != InstallStatus::Success);

                        if any_failed {
                            // Some installs failed — go back to ToolCheck and let user decide
                            app.progress_message =
                                "Some installations failed — see logs for details.".to_string();
                            // Re-check which tools are now available
                            event_rx = Some(start_tool_check(app.selected_scanners.clone()));
                        } else {
                            // All succeeded — start scanning
                            app.progress_message = "Tools installed, starting scan...".to_string();
                            app.scan_status = ScanStatus::Running;
                            app.started_at = Some(chrono::Utc::now());
                            app.screen = AppScreen::Scanning;
                            app.init_scanner_statuses();
                            event_rx =
                                Some(start_scan_task(app.target.clone(), app.parallel_scanners()));
                        }
                        break;
                    }
                    AppEvent::ScannerStarted(scanner_type) => {
                        app.update_scanner_status(&scanner_type, ScannerRunStatus::Running);
                        let running: Vec<String> = app
                            .scanner_statuses
                            .iter()
                            .filter(|(_, s)| *s == ScannerRunStatus::Running)
                            .map(|(t, _)| t.to_string())
                            .collect();
                        app.progress_message = format!("Running {}...", running.join(", "));
                    }
                    AppEvent::ScanResult(result) => {
                        let status = if result.success {
                            ScannerRunStatus::Completed
                        } else {
                            ScannerRunStatus::Failed
                        };
                        app.update_scanner_status(&result.scanner, status);
                        app.results.push(result);
                        app.current_scanner_index += 1;
                    }
                    AppEvent::ScanDone => {
                        // === Smart Pipeline: Subfinder → httpx chain ===
                        let subdomains = scanners::extract_subdomains(&app.results);
                        let httpx_already_ran = app
                            .results
                            .iter()
                            .any(|r| r.scanner == scanners::ScannerType::Httpx);
                        let httpx_available = scanners::check_tool("httpx").await;

                        if !subdomains.is_empty() && !httpx_already_ran && httpx_available {
                            app.progress_message = format!(
                                "Smart chain: probing {} subdomains with httpx...",
                                subdomains.len()
                            );
                            event_rx = Some(start_httpx_chain_task(subdomains));
                            break;
                        }

                        // === Smart Pipeline: WordPress detection → WPScan chain ===
                        let wp_detected = scanners::detect_wordpress(&app.results);
                        let wpscan_already_ran = app
                            .results
                            .iter()
                            .any(|r| r.scanner == scanners::ScannerType::Wpscan);
                        let wpscan_available =
                            scanners::check_tool(if cfg!(target_os = "windows") {
                                "wpscan.bat"
                            } else {
                                "wpscan"
                            })
                            .await;

                        if wp_detected && !wpscan_already_ran && wpscan_available {
                            app.progress_message =
                                "WordPress detected — auto-running WPScan...".to_string();
                            app.scanner_statuses
                                .push((scanners::ScannerType::Wpscan, ScannerRunStatus::Running));
                            event_rx = Some(start_wpscan_chain_task(app.target.clone()));
                            break;
                        }

                        // === Smart Pipeline: SQLi → SQLMap chain (existing) ===
                        if app.sqlmap_selected() {
                            let sqli_targets = scanners::extract_sqli_targets(&app.results);
                            if !sqli_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Sqlmap,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "SQL injection detected — running SQLMap on {} endpoint(s)...",
                                    sqli_targets.len()
                                );
                                event_rx = Some(start_sqlmap_task(sqli_targets));
                                break;
                            } else {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Sqlmap,
                                    ScannerRunStatus::Completed,
                                );
                                app.progress_message =
                                    "No SQL injection detected — SQLMap skipped.".to_string();
                            }
                        }

                        // === Smart Pipeline: Nmap → Hydra chain ===
                        if app.hydra_selected() {
                            let hydra_targets =
                                scanners::extract_hydra_targets(&app.results, &app.target);
                            if !hydra_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "Brute-forcing {} service(s) with Hydra...",
                                    hydra_targets.len()
                                );
                                event_rx = Some(start_hydra_task(hydra_targets));
                                break;
                            } else {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Completed,
                                );
                                app.progress_message =
                                    "No brute-forceable services found — Hydra skipped."
                                        .to_string();
                            }
                        }

                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }

                    // === httpx chain completed ===
                    AppEvent::HttpxChainResult(result) => {
                        app.results.push(result);
                    }
                    AppEvent::HttpxChainDone => {
                        // After httpx chain, check for WordPress and SQLi chains
                        let wp_detected = scanners::detect_wordpress(&app.results);
                        let wpscan_already_ran = app
                            .results
                            .iter()
                            .any(|r| r.scanner == scanners::ScannerType::Wpscan);
                        let wpscan_available =
                            scanners::check_tool(if cfg!(target_os = "windows") {
                                "wpscan.bat"
                            } else {
                                "wpscan"
                            })
                            .await;

                        if wp_detected && !wpscan_already_ran && wpscan_available {
                            app.progress_message =
                                "WordPress detected — auto-running WPScan...".to_string();
                            app.scanner_statuses
                                .push((scanners::ScannerType::Wpscan, ScannerRunStatus::Running));
                            event_rx = Some(start_wpscan_chain_task(app.target.clone()));
                            break;
                        }

                        if app.sqlmap_selected() {
                            let sqli_targets = scanners::extract_sqli_targets(&app.results);
                            if !sqli_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Sqlmap,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "SQL injection detected — running SQLMap on {} endpoint(s)...",
                                    sqli_targets.len()
                                );
                                event_rx = Some(start_sqlmap_task(sqli_targets));
                                break;
                            }
                        }

                        if app.hydra_selected() {
                            let hydra_targets =
                                scanners::extract_hydra_targets(&app.results, &app.target);
                            if !hydra_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "Brute-forcing {} service(s) with Hydra...",
                                    hydra_targets.len()
                                );
                                event_rx = Some(start_hydra_task(hydra_targets));
                                break;
                            }
                        }

                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }

                    // === WPScan chain completed ===
                    AppEvent::WpscanChainResult(result) => {
                        app.update_scanner_status(
                            &scanners::ScannerType::Wpscan,
                            if result.success {
                                ScannerRunStatus::Completed
                            } else {
                                ScannerRunStatus::Failed
                            },
                        );
                        app.results.push(result);
                    }
                    AppEvent::WpscanChainDone => {
                        // After WPScan chain, check SQLi chain
                        if app.sqlmap_selected() {
                            let sqli_targets = scanners::extract_sqli_targets(&app.results);
                            if !sqli_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Sqlmap,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "SQL injection detected — running SQLMap on {} endpoint(s)...",
                                    sqli_targets.len()
                                );
                                event_rx = Some(start_sqlmap_task(sqli_targets));
                                break;
                            }
                        }

                        // After WPScan chain, check Hydra chain
                        if app.hydra_selected() {
                            let hydra_targets =
                                scanners::extract_hydra_targets(&app.results, &app.target);
                            if !hydra_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "Brute-forcing {} service(s) with Hydra...",
                                    hydra_targets.len()
                                );
                                event_rx = Some(start_hydra_task(hydra_targets));
                                break;
                            }
                        }

                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }
                    AppEvent::SqlmapResult(result) => {
                        let status = if result.success {
                            ScannerRunStatus::Completed
                        } else {
                            ScannerRunStatus::Failed
                        };
                        app.update_scanner_status(&scanners::ScannerType::Sqlmap, status);
                        app.results.push(result);
                        app.current_scanner_index += 1;
                    }
                    AppEvent::SqlmapDone => {
                        // After SQLMap, check Hydra chain
                        if app.hydra_selected() {
                            let hydra_targets =
                                scanners::extract_hydra_targets(&app.results, &app.target);
                            if !hydra_targets.is_empty() {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Running,
                                );
                                app.progress_message = format!(
                                    "Brute-forcing {} service(s) with Hydra...",
                                    hydra_targets.len()
                                );
                                event_rx = Some(start_hydra_task(hydra_targets));
                                break;
                            } else {
                                app.update_scanner_status(
                                    &scanners::ScannerType::Hydra,
                                    ScannerRunStatus::Completed,
                                );
                                app.progress_message =
                                    "No brute-forceable services found — Hydra skipped."
                                        .to_string();
                            }
                        }
                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }
                    AppEvent::HydraResult(result) => {
                        let status = if result.success {
                            ScannerRunStatus::Completed
                        } else {
                            ScannerRunStatus::Failed
                        };
                        app.update_scanner_status(&scanners::ScannerType::Hydra, status);
                        app.results.push(result);
                        app.current_scanner_index += 1;
                    }
                    AppEvent::HydraDone => {
                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }
                }
            }
        }

        // Increment spinner animation tick
        app.spin_tick = app.spin_tick.wrapping_add(1);

        // Poll for keyboard events
        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Mouse(mouse) => {
                    if app.screen == AppScreen::Results {
                        match mouse.kind {
                            MouseEventKind::ScrollDown => {
                                app.result_scroll = app.result_scroll.saturating_add(3);
                            }
                            MouseEventKind::ScrollUp => {
                                app.result_scroll = app.result_scroll.saturating_sub(3);
                            }
                            _ => {}
                        }
                    }
                }
                Event::Key(key) => {
                    // Ignore Release/Repeat events (fixes double input on Windows)
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        app.should_quit = true;
                    }

                    if app.should_quit {
                        break;
                    }

                    match app.screen {
                        AppScreen::Home => match key.code {
                            KeyCode::Char('s') | KeyCode::Enter => {
                                app.screen = AppScreen::TargetInput;
                            }
                            KeyCode::Char('q') => {
                                app.should_quit = true;
                            }
                            KeyCode::Char('h') => {
                                app.show_help = !app.show_help;
                            }
                            _ => {}
                        },

                        AppScreen::TargetInput => match key.code {
                            KeyCode::Char(c) => {
                                app.target_input.push(c);
                            }
                            KeyCode::Backspace => {
                                app.target_input.pop();
                            }
                            KeyCode::Enter => {
                                if !app.target_input.is_empty() {
                                    app.screen = AppScreen::ScannerSelect;
                                }
                            }
                            KeyCode::Esc => {
                                app.screen = AppScreen::Home;
                            }
                            _ => {}
                        },

                        AppScreen::ScannerSelect => match key.code {
                            KeyCode::Up | KeyCode::Char('k') => {
                                if app.scanner_cursor > 0 {
                                    app.scanner_cursor -= 1;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                if app.scanner_cursor < app.scanner_toggles.len() - 1 {
                                    app.scanner_cursor += 1;
                                }
                            }
                            KeyCode::Char(' ') => {
                                app.toggle_scanner(app.scanner_cursor);
                            }
                            KeyCode::Enter => {
                                let selected = app.get_selected_scanners();
                                if !selected.is_empty() {
                                    app.start_scan();
                                    // Check tools before scanning
                                    app.screen = AppScreen::ToolCheck;
                                    app.progress_message =
                                        "Checking installed tools...".to_string();
                                    event_rx =
                                        Some(start_tool_check(app.selected_scanners.clone()));
                                }
                            }
                            KeyCode::Esc => {
                                app.screen = AppScreen::TargetInput;
                            }
                            _ => {}
                        },

                        AppScreen::ToolCheck => match key.code {
                            KeyCode::Char('i') => {
                                // Install all missing tools
                                let missing: Vec<scanners::ScannerType> = app
                                    .missing_tools()
                                    .iter()
                                    .map(|t| t.scanner.clone())
                                    .collect();
                                if !missing.is_empty() {
                                    app.screen = AppScreen::Installing;
                                    app.install_progress.clear();
                                    app.progress_message = "Installing tools...".to_string();
                                    event_rx = Some(start_install_task(missing));
                                }
                            }
                            KeyCode::Char('s') => {
                                // Skip missing tools, scan with available ones only
                                let available: Vec<scanners::ScannerType> = app
                                    .tool_statuses
                                    .iter()
                                    .filter(|t| t.installed)
                                    .map(|t| t.scanner.clone())
                                    .collect();
                                if available.is_empty() {
                                    app.progress_message = "No scanners available!".to_string();
                                } else {
                                    app.selected_scanners = available;
                                    app.scan_status = ScanStatus::Running;
                                    app.started_at = Some(chrono::Utc::now());
                                    app.screen = AppScreen::Scanning;
                                    app.init_scanner_statuses();
                                    event_rx = Some(start_scan_task(
                                        app.target.clone(),
                                        app.parallel_scanners(),
                                    ));
                                }
                            }
                            KeyCode::Char('q') | KeyCode::Esc => {
                                app.should_quit = true;
                            }
                            _ => {}
                        },

                        AppScreen::Installing => match key.code {
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.install_scroll = app.install_scroll.saturating_add(1);
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.install_scroll = app.install_scroll.saturating_sub(1);
                            }
                            KeyCode::Char('q') => {
                                app.should_quit = true;
                            }
                            _ => {}
                        },

                        AppScreen::Scanning => {
                            if let KeyCode::Char('q') = key.code {
                                app.should_quit = true;
                            }
                        }

                        AppScreen::Results => match key.code {
                            KeyCode::Char('q') => {
                                app.should_quit = true;
                            }
                            KeyCode::Tab => {
                                if !app.results.is_empty() {
                                    app.result_tab = (app.result_tab + 1) % app.results.len();
                                    app.result_scroll = 0;
                                }
                            }
                            KeyCode::BackTab => {
                                if !app.results.is_empty() {
                                    app.result_tab = if app.result_tab == 0 {
                                        app.results.len() - 1
                                    } else {
                                        app.result_tab - 1
                                    };
                                    app.result_scroll = 0;
                                }
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.result_scroll = app.result_scroll.saturating_add(1);
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.result_scroll = app.result_scroll.saturating_sub(1);
                            }
                            KeyCode::Char('e') => {
                                app.screen = AppScreen::Export;
                            }
                            KeyCode::Char('n') => {
                                app.screen = AppScreen::TargetInput;
                                app.results.clear();
                                app.scan_status = ScanStatus::Idle;
                            }
                            _ => {}
                        },

                        AppScreen::Export => match key.code {
                            KeyCode::Char(c) => {
                                app.export_input.push(c);
                            }
                            KeyCode::Backspace => {
                                app.export_input.pop();
                            }
                            KeyCode::Up | KeyCode::Down => {
                                app.export_cursor = if app.export_cursor == 0 { 1 } else { 0 };
                            }
                            KeyCode::Enter => {
                                let path = app.export_input.clone();
                                if !path.is_empty() {
                                    match crate::export::export_results(app, &path) {
                                        Ok(_) => {
                                            app.progress_message = format!("Exported to {}", path);
                                        }
                                        Err(e) => {
                                            app.progress_message = format!("Export failed: {}", e);
                                        }
                                    }
                                    app.screen = AppScreen::Results;
                                }
                            }
                            KeyCode::Esc => {
                                app.screen = AppScreen::Results;
                            }
                            _ => {}
                        },
                    }
                } // Event::Key
                _ => {}
            } // match event
        }

        if app.should_quit {
            if let Some(ref path) = app.export_path.clone() {
                let _ = crate::export::export_results(app, path);
            }
            break;
        }
    }

    Ok(())
}

fn start_tool_check(scanners: Vec<scanners::ScannerType>) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let statuses = installer::check_all_tools(&scanners).await;
        let _ = tx.send(AppEvent::ToolCheckDone(statuses)).await;
    });

    rx
}

fn start_install_task(missing: Vec<scanners::ScannerType>) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        for scanner in &missing {
            let progress = match installer::install_tool(scanner).await {
                Ok(p) => p,
                Err(e) => installer::InstallProgress {
                    scanner: scanner.clone(),
                    status: InstallStatus::Failed(e.to_string()),
                    output: String::new(),
                },
            };
            let _ = tx.send(AppEvent::InstallProgress(progress)).await;
        }
        let _ = tx.send(AppEvent::InstallDone).await;
    });

    rx
}

fn start_scan_task(
    target: String,
    scanner_types: Vec<scanners::ScannerType>,
) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let mut handles = Vec::new();

        for scanner_type in scanner_types {
            let tx = tx.clone();
            let target = target.clone();

            let handle = tokio::spawn(async move {
                let _ = tx
                    .send(AppEvent::ScannerStarted(scanner_type.clone()))
                    .await;

                match scanners::run_scanner(&scanner_type, &target).await {
                    Ok(result) => {
                        let _ = tx.send(AppEvent::ScanResult(result)).await;
                    }
                    Err(e) => {
                        let result = scanners::ScanResult {
                            scanner: scanner_type.clone(),
                            target: target.clone(),
                            started_at: chrono::Utc::now(),
                            finished_at: chrono::Utc::now(),
                            raw_output: String::new(),
                            findings: Vec::new(),
                            success: false,
                            error: Some(e.to_string()),
                        };
                        let _ = tx.send(AppEvent::ScanResult(result)).await;
                    }
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }
        let _ = tx.send(AppEvent::ScanDone).await;
    });

    rx
}

/// Smart chain: run sqlmap on discovered SQL injection endpoints
fn start_sqlmap_task(targets: Vec<String>) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        match scanners::sqlmap::run_on_targets(&targets).await {
            Ok(result) => {
                let _ = tx.send(AppEvent::SqlmapResult(result)).await;
            }
            Err(e) => {
                let result = scanners::ScanResult {
                    scanner: scanners::ScannerType::Sqlmap,
                    target: targets.join(", "),
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                    raw_output: String::new(),
                    findings: Vec::new(),
                    success: false,
                    error: Some(e.to_string()),
                };
                let _ = tx.send(AppEvent::SqlmapResult(result)).await;
            }
        }
        let _ = tx.send(AppEvent::SqlmapDone).await;
    });

    rx
}

/// Smart chain: run Hydra on brute-forceable services discovered by Nmap
fn start_hydra_task(targets: Vec<scanners::hydra::HydraTarget>) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        match scanners::hydra::run_on_targets(&targets).await {
            Ok(result) => {
                let _ = tx.send(AppEvent::HydraResult(result)).await;
            }
            Err(e) => {
                let result = scanners::ScanResult {
                    scanner: scanners::ScannerType::Hydra,
                    target: format!("{} service(s)", targets.len()),
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                    raw_output: String::new(),
                    findings: Vec::new(),
                    success: false,
                    error: Some(e.to_string()),
                };
                let _ = tx.send(AppEvent::HydraResult(result)).await;
            }
        }
        let _ = tx.send(AppEvent::HydraDone).await;
    });

    rx
}

/// Smart chain: run httpx on subdomains discovered by Subfinder
fn start_httpx_chain_task(subdomains: Vec<String>) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        match scanners::httpx::run_list(&subdomains).await {
            Ok(result) => {
                let _ = tx.send(AppEvent::HttpxChainResult(result)).await;
            }
            Err(e) => {
                let result = scanners::ScanResult {
                    scanner: scanners::ScannerType::Httpx,
                    target: format!("{} subdomains", subdomains.len()),
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                    raw_output: String::new(),
                    findings: Vec::new(),
                    success: false,
                    error: Some(e.to_string()),
                };
                let _ = tx.send(AppEvent::HttpxChainResult(result)).await;
            }
        }
        let _ = tx.send(AppEvent::HttpxChainDone).await;
    });

    rx
}

/// Smart chain: auto-run WPScan when WordPress is detected
fn start_wpscan_chain_task(target: String) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(32);

    tokio::spawn(async move {
        match scanners::wpscan::run(&target).await {
            Ok(result) => {
                let _ = tx.send(AppEvent::WpscanChainResult(result)).await;
            }
            Err(e) => {
                let result = scanners::ScanResult {
                    scanner: scanners::ScannerType::Wpscan,
                    target,
                    started_at: chrono::Utc::now(),
                    finished_at: chrono::Utc::now(),
                    raw_output: String::new(),
                    findings: Vec::new(),
                    success: false,
                    error: Some(e.to_string()),
                };
                let _ = tx.send(AppEvent::WpscanChainResult(result)).await;
            }
        }
        let _ = tx.send(AppEvent::WpscanChainDone).await;
    });

    rx
}
