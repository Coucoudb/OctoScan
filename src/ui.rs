use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Tabs, Wrap},
    Frame,
};

use crate::app::{App, AppScreen, ScanStatus, ScannerRunStatus};
use crate::installer::InstallStatus;
use crate::scanners::Severity;

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

const OCTOSCAN_LOGO: &str = r#"
  ██████╗  ██████╗████████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔═══██╗██╔════╝╚══██╔══╝██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║        ██║   ██║   ██║███████╗██║     ███████║██╔██╗ ██║
 ██║   ██║██║        ██║   ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╔╝╚██████╗   ██║   ╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝   ╚═╝    ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"#;

pub fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    // Main layout: header + body + footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    draw_header(f, chunks[0], app);
    draw_footer(f, chunks[2], app);

    match app.screen {
        AppScreen::Home => draw_home(f, chunks[1]),
        AppScreen::TargetInput => draw_target_input(f, chunks[1], app),
        AppScreen::ScannerSelect => draw_scanner_select(f, chunks[1], app),
        AppScreen::ToolCheck => draw_tool_check(f, chunks[1], app),
        AppScreen::Installing => draw_installing(f, chunks[1], app),
        AppScreen::Scanning => draw_scanning(f, chunks[1], app),
        AppScreen::Results => draw_results(f, chunks[1], app),
        AppScreen::Export => draw_export(f, chunks[1], app),
    }

    if app.show_help {
        draw_help_popup(f, size);
    }
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let status = match &app.scan_status {
        ScanStatus::Idle => Span::styled(" IDLE ", Style::default().fg(Color::DarkGray)),
        ScanStatus::Running => Span::styled(
            " SCANNING ",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Completed => Span::styled(
            " COMPLETED ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " 🐙 OctoScan ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" │ "),
        status,
        Span::raw(" │ "),
        Span::styled(
            if app.target.is_empty() {
                "No target"
            } else {
                &app.target
            },
            Style::default().fg(Color::White),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(header, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let help_text = match app.screen {
        AppScreen::Home => "s: Start scan │ h: Help │ q: Quit",
        AppScreen::TargetInput => "Enter: Confirm │ Esc: Back",
        AppScreen::ScannerSelect => "↑/↓: Navigate │ Space: Toggle │ Enter: Start │ Esc: Back",
        AppScreen::ToolCheck => "i: Install missing │ s: Skip & scan available │ q: Quit",
        AppScreen::Installing => "Installing... │ ↑/↓: Scroll │ q: Cancel",
        AppScreen::Scanning => "Scanning in progress... │ q: Cancel",
        AppScreen::Results => {
            "Tab/Shift+Tab: Switch scanner │ ↑/↓: Scroll │ e: Export │ n: New scan │ q: Quit"
        }
        AppScreen::Export => "Enter: Confirm │ Esc: Cancel",
    };

    let message = if !app.progress_message.is_empty() {
        format!("{} │ {}", app.progress_message, help_text)
    } else {
        help_text.to_string()
    };

    let footer = Paragraph::new(message)
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );

    f.render_widget(footer, area);
}

fn draw_home(f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);

    let logo = Paragraph::new(OCTOSCAN_LOGO)
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);
    f.render_widget(logo, chunks[0]);

    let subtitle =
        Paragraph::new("Security Auditing Tool — Orchestrate Nmap, Nuclei, ZAP and more")
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Center);
    f.render_widget(subtitle, chunks[1]);

    let menu_items = vec![
        ListItem::new(Line::from(vec![
            Span::styled(
                " [s] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Start a new scan"),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " [h] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Show help"),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled(
                " [q] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Quit"),
        ])),
    ];

    let menu = List::new(menu_items).block(
        Block::default()
            .title(" Menu ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(menu, chunks[2]);
}

fn draw_target_input(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new(" Enter the target URL or IP address:")
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::NONE));
    f.render_widget(title, chunks[0]);

    let input_display = format!(" > {}_", app.target_input);
    let input = Paragraph::new(input_display)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .title(" Target ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(input, chunks[1]);
}

fn draw_scanner_select(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let title = Paragraph::new(format!(" Select scanners for: {}", app.target_input))
        .style(Style::default().fg(Color::White));
    f.render_widget(title, chunks[0]);

    let scanner_entries: Vec<(Option<&str>, usize, &str)> = vec![
        (
            Some("Reconnaissance"),
            0,
            "Nmap — Port scanning & service detection",
        ),
        (None, 1, "Feroxbuster — Directory & content discovery"),
        (None, 2, "Subfinder — Subdomain enumeration"),
        (None, 3, "httpx — HTTP probing & technology detection"),
        (
            Some("Vulnerability Scanning"),
            4,
            "Nuclei — Vulnerability scanning with templates",
        ),
        (
            Some("Web Application"),
            5,
            "ZAP — Web application security scanner",
        ),
        (None, 6, "WPScan — WordPress vulnerability scanner"),
        (
            Some("Exploitation"),
            7,
            "SQLMap — SQL injection verification (runs after ZAP/Nuclei)",
        ),
    ];

    let mut items: Vec<ListItem> = Vec::new();
    for (category, idx, name) in &scanner_entries {
        if let Some(cat) = category {
            items.push(
                ListItem::new(Line::from(Span::styled(
                    format!(" ── {} ──", cat),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )))
                .style(Style::default()),
            );
        }
        let checkbox = if app.scanner_toggles[*idx] {
            "[x]"
        } else {
            "[ ]"
        };
        let style = if app.scanner_cursor == *idx {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let prefix = if app.scanner_cursor == *idx {
            "▸ "
        } else {
            "  "
        };
        items.push(ListItem::new(format!("  {}{} {}", prefix, checkbox, name)).style(style));
    }

    let list = List::new(items).block(
        Block::default()
            .title(" Scanners ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(list, chunks[1]);

    let selected_count: usize = app.scanner_toggles.iter().filter(|&&t| t).count();
    let hint = Paragraph::new(format!(
        " {} scanner(s) selected — Press Enter to start",
        selected_count
    ))
    .style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, chunks[2]);
}

fn draw_scanning(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    // Progress info
    let total = app.selected_scanners.len();
    let completed = app.current_scanner_index;
    let progress_text = format!(" Progress: {}/{} scanners completed", completed, total);

    let progress = Paragraph::new(progress_text)
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .title(" Scanning ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(progress, chunks[0]);

    // Show all scanners with their current status
    let spinner_frame = SPINNER_FRAMES[app.spin_tick % SPINNER_FRAMES.len()];

    let items: Vec<ListItem> = app
        .scanner_statuses
        .iter()
        .map(|(scanner_type, status)| {
            let (icon, color, detail) = match status {
                ScannerRunStatus::Pending => {
                    ("○".to_string(), Color::DarkGray, "Waiting...".to_string())
                }
                ScannerRunStatus::Running => (
                    spinner_frame.to_string(),
                    Color::Yellow,
                    "Scanning...".to_string(),
                ),
                ScannerRunStatus::Completed => {
                    let findings = app
                        .results
                        .iter()
                        .find(|r| &r.scanner == scanner_type)
                        .map(|r| format!("{} findings", r.findings.len()))
                        .unwrap_or_else(|| "Done".to_string());
                    ("✓".to_string(), Color::Green, findings)
                }
                ScannerRunStatus::Failed => {
                    let error = app
                        .results
                        .iter()
                        .find(|r| &r.scanner == scanner_type)
                        .and_then(|r| r.error.clone())
                        .unwrap_or_else(|| "Error".to_string());
                    ("✗".to_string(), Color::Red, error)
                }
            };

            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", icon),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", scanner_type),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!(" — {}", detail),
                    Style::default().fg(Color::DarkGray),
                ),
            ]))
        })
        .collect();

    let scanner_list = List::new(items).block(
        Block::default()
            .title(" Scanners ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(scanner_list, chunks[1]);
}

fn draw_results(f: &mut Frame, area: Rect, app: &App) {
    if app.results.is_empty() {
        let msg = Paragraph::new(" No results available.")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title(" Results ").borders(Borders::ALL));
        f.render_widget(msg, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(10),
        ])
        .split(area);

    // Tabs for each scanner result
    let tab_titles: Vec<Line> = app
        .results
        .iter()
        .map(|r| {
            let icon = if r.success { "✓" } else { "✗" };
            Line::from(format!(" {} {} ({}) ", icon, r.scanner, r.findings.len()))
        })
        .collect();

    let tabs = Tabs::new(tab_titles)
        .select(app.result_tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .title(" Results ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(tabs, chunks[0]);

    if let Some(result) = app.results.get(app.result_tab) {
        // Summary
        let duration = result.finished_at - result.started_at;
        let summary_text = format!(
            " Scanner: {} │ Target: {} │ Duration: {}s │ Findings: {} │ Status: {}",
            result.scanner,
            result.target,
            duration.num_seconds(),
            result.findings.len(),
            if result.success { "Success" } else { "Error" },
        );

        let summary = Paragraph::new(summary_text)
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .title(" Summary ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
        f.render_widget(summary, chunks[1]);

        // Findings or raw output
        if result.findings.is_empty() {
            // Show raw output
            let raw = if let Some(ref err) = result.error {
                format!("Error: {}\n\n{}", err, result.raw_output)
            } else {
                result.raw_output.clone()
            };

            let raw_paragraph = Paragraph::new(raw)
                .style(Style::default().fg(Color::White))
                .scroll((app.result_scroll, 0))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .title(" Raw Output ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(raw_paragraph, chunks[2]);
        } else {
            // Build findings as a single text block for scrolling + wrapping
            let mut lines: Vec<Line> = Vec::new();

            for finding in &result.findings {
                let severity_color = match finding.severity {
                    Severity::Critical => Color::Magenta,
                    Severity::High => Color::Red,
                    Severity::Medium => Color::Yellow,
                    Severity::Low => Color::Blue,
                    Severity::Info => Color::Gray,
                };

                lines.push(Line::from(vec![
                    Span::styled(
                        format!(" [{}] ", finding.severity),
                        Style::default()
                            .fg(severity_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        finding.title.clone(),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("        "),
                    Span::styled(
                        finding.description.clone(),
                        Style::default().fg(Color::Gray),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw("        "),
                    Span::styled(
                        finding.details.clone(),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
                lines.push(Line::from(""));
            }

            let findings_paragraph = Paragraph::new(lines)
                .scroll((app.result_scroll, 0))
                .wrap(Wrap { trim: false })
                .block(
                    Block::default()
                        .title(format!(" Findings ({}) ", result.findings.len()))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::DarkGray)),
                );
            f.render_widget(findings_paragraph, chunks[2]);
        }
    }
}

fn draw_export(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(0),
        ])
        .split(area);

    let title = Paragraph::new(" Export results to file (supports .json and .txt):")
        .style(Style::default().fg(Color::White));
    f.render_widget(title, chunks[0]);

    let input_display = format!(" > {}_", app.export_input);
    let input = Paragraph::new(input_display)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .title(" File path ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    f.render_widget(input, chunks[1]);
}

fn draw_tool_check(f: &mut Frame, area: Rect, app: &App) {
    if app.tool_statuses.is_empty() {
        // Still checking
        let checking = Paragraph::new("\n  Checking installed tools...")
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .title(" Tool Check ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
        f.render_widget(checking, area);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(5),
        ])
        .split(area);

    let missing_count = app.missing_tools().len();
    let total = app.tool_statuses.len();

    let title_text = if missing_count == 0 {
        format!(" All {} tools are installed!", total)
    } else {
        format!(" {} of {} tools are missing", missing_count, total)
    };
    let title_color = if missing_count == 0 {
        Color::Green
    } else {
        Color::Yellow
    };

    let title = Paragraph::new(title_text).style(
        Style::default()
            .fg(title_color)
            .add_modifier(Modifier::BOLD),
    );
    f.render_widget(title, chunks[0]);

    // Tool status list
    let items: Vec<ListItem> = app
        .tool_statuses
        .iter()
        .map(|status| {
            let (icon, color) = if status.installed {
                ("✓ Installed", Color::Green)
            } else {
                ("✗ Missing ", Color::Red)
            };

            let mut lines = vec![Line::from(vec![
                Span::styled(
                    format!("  {} ", icon),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", status.scanner),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
            ])];

            if !status.installed {
                lines.push(Line::from(vec![
                    Span::raw("              "),
                    Span::styled(&status.install_hint, Style::default().fg(Color::DarkGray)),
                ]));
            }

            lines.push(Line::from(""));
            ListItem::new(lines)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Scanner Tools ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(list, chunks[1]);

    // Action hint
    if missing_count > 0 {
        let mut action_lines = vec![
            Line::from(vec![
                Span::styled(
                    " [i] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Install all missing tools automatically"),
            ]),
            Line::from(vec![
                Span::styled(
                    " [s] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Skip and scan with available tools only"),
            ]),
            Line::from(vec![
                Span::styled(
                    " [q] ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("Quit"),
            ]),
        ];

        if let Some(ref log_path) = app.log_path {
            action_lines.push(Line::from(""));
            action_lines.push(Line::from(Span::styled(
                format!(" Logs: {}", log_path),
                Style::default().fg(Color::DarkGray),
            )));
        }

        let hint = Paragraph::new(action_lines).block(
            Block::default()
                .title(" Actions ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
        f.render_widget(hint, chunks[2]);
    }
}

fn draw_installing(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(8),
            Constraint::Length(3),
        ])
        .split(area);

    let total_missing = app.missing_tools().len();
    let completed = app.install_progress.len();

    let progress_text = format!(
        " Installing tools: {}/{} completed\n\n {}",
        completed, total_missing, app.progress_message
    );

    let progress = Paragraph::new(progress_text)
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .title(" Installation ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    f.render_widget(progress, chunks[0]);

    // Install progress list
    let items: Vec<ListItem> = app
        .install_progress
        .iter()
        .map(|p| {
            let (icon, color, status_text) = match &p.status {
                InstallStatus::Success => ("✓", Color::Green, "Installed successfully".to_string()),
                InstallStatus::Failed(msg) => ("✗", Color::Red, format!("Failed: {}", msg)),
            };

            let mut lines = vec![Line::from(vec![
                Span::styled(
                    format!("  {} ", icon),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}", p.scanner),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" — {}", status_text), Style::default().fg(color)),
            ])];

            // Show output snippet on failure
            if matches!(p.status, InstallStatus::Failed(_)) && !p.output.is_empty() {
                let snippet: String = p.output.lines().take(3).collect::<Vec<_>>().join("\n");
                lines.push(Line::from(Span::styled(
                    format!("    {}", snippet),
                    Style::default().fg(Color::DarkGray),
                )));
            }

            lines.push(Line::from(""));
            ListItem::new(lines)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(" Progress ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(list, chunks[1]);

    // Log file path
    let log_text = if let Some(ref path) = app.log_path {
        format!(" Logs: {}", path)
    } else {
        " Logs: not available".to_string()
    };
    let log_info = Paragraph::new(log_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(log_info, chunks[2]);
}

fn draw_help_popup(f: &mut Frame, area: Rect) {
    let popup_area = centered_rect(60, 60, area);
    f.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled(
            " OctoScan Help",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(" CLI Usage:"),
        Line::from("   octoscan scan -t <target> -s nmap,nuclei,zap"),
        Line::from("   octoscan scan -t <target> -s nmap -o report.json"),
        Line::from(""),
        Line::from(" Interactive Mode:"),
        Line::from("   Just run: octoscan"),
        Line::from(""),
        Line::from(" Keybindings:"),
        Line::from("   s          Start a new scan"),
        Line::from("   Tab        Switch between scanner results"),
        Line::from("   ↑/↓        Navigate / Scroll"),
        Line::from("   Space      Toggle scanner selection"),
        Line::from("   e          Export results"),
        Line::from("   n          New scan (from results)"),
        Line::from("   h          Toggle help"),
        Line::from("   q/Ctrl+C   Quit"),
        Line::from(""),
        Line::from(" Supported Scanners:"),
        Line::from("   nmap     Port scanning & service detection"),
        Line::from("   nuclei   Template-based vulnerability scanning"),
        Line::from("   zap      OWASP ZAP web app security scanner"),
        Line::from(""),
        Line::from(Span::styled(
            " Press h to close",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .style(Style::default().fg(Color::White));

    f.render_widget(help, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
