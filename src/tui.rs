use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::app::{App, AppScreen, ScanStatus};
use crate::installer::{self, InstallStatus};
use crate::scanners;
use crate::ui;

enum AppEvent {
    // Scan events
    ScanProgress(String),
    ScanResult(scanners::ScanResult),
    ScanDone,
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
                            event_rx = Some(start_scan_task(
                                app.target.clone(),
                                app.selected_scanners.clone(),
                            ));
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
                            event_rx = Some(start_scan_task(
                                app.target.clone(),
                                app.selected_scanners.clone(),
                            ));
                        }
                        break;
                    }
                    AppEvent::ScanProgress(msg) => {
                        app.progress_message = msg;
                    }
                    AppEvent::ScanResult(result) => {
                        app.results.push(result);
                        app.current_scanner_index += 1;
                    }
                    AppEvent::ScanDone => {
                        app.scan_status = ScanStatus::Completed;
                        app.finished_at = Some(chrono::Utc::now());
                        app.screen = AppScreen::Results;
                        event_rx = None;
                        break;
                    }
                }
            }
        }

        // Poll for keyboard events
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Ignore Release/Repeat events (fixes double input on Windows)
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
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
                            if app.scanner_cursor < 2 {
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
                                app.progress_message = "Checking installed tools...".to_string();
                                event_rx = Some(start_tool_check(app.selected_scanners.clone()));
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
                                event_rx = Some(start_scan_task(
                                    app.target.clone(),
                                    app.selected_scanners.clone(),
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
            }
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
        for scanner_type in &scanner_types {
            let _ = tx
                .send(AppEvent::ScanProgress(format!(
                    "Running {} on {}...",
                    scanner_type, target
                )))
                .await;

            match scanners::run_scanner(scanner_type, &target).await {
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
        }
        let _ = tx.send(AppEvent::ScanDone).await;
    });

    rx
}
