use crate::installer::{InstallProgress, ToolStatus};
use crate::scanners::{ScanResult, ScannerType};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppScreen {
    Home,
    TargetInput,
    ScannerSelect,
    ToolCheck,
    Installing,
    Scanning,
    Results,
    Export,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Idle,
    Running,
    Completed,
    Error(String),
}

pub struct App {
    pub id: Uuid,
    pub screen: AppScreen,
    pub target: String,
    pub target_input: String,
    pub selected_scanners: Vec<ScannerType>,
    pub scanner_cursor: usize,
    pub scanner_toggles: [bool; 3],
    pub scan_status: ScanStatus,
    pub results: Vec<ScanResult>,
    pub current_scanner_index: usize,
    pub progress_message: String,
    pub export_path: Option<String>,
    pub result_scroll: u16,
    pub result_tab: usize,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub should_quit: bool,
    pub export_cursor: usize,
    pub export_input: String,
    pub show_help: bool,
    // Tool check & install state
    pub tool_statuses: Vec<ToolStatus>,
    pub tool_check_cursor: usize,
    pub install_progress: Vec<InstallProgress>,
    pub install_scroll: u16,
}

impl App {
    pub fn new(target: String, scanners: Vec<ScannerType>) -> Self {
        Self {
            id: Uuid::new_v4(),
            screen: AppScreen::Scanning,
            target: target.clone(),
            target_input: target,
            selected_scanners: scanners,
            scanner_cursor: 0,
            scanner_toggles: [false; 3],
            scan_status: ScanStatus::Idle,
            results: Vec::new(),
            current_scanner_index: 0,
            progress_message: String::new(),
            export_path: None,
            result_scroll: 0,
            result_tab: 0,
            started_at: None,
            finished_at: None,
            should_quit: false,
            export_cursor: 0,
            export_input: String::from("report.json"),
            show_help: false,
            tool_statuses: Vec::new(),
            tool_check_cursor: 0,
            install_progress: Vec::new(),
            install_scroll: 0,
        }
    }

    pub fn new_interactive() -> Self {
        Self {
            id: Uuid::new_v4(),
            screen: AppScreen::Home,
            target: String::new(),
            target_input: String::new(),
            selected_scanners: Vec::new(),
            scanner_cursor: 0,
            scanner_toggles: [false; 3],
            scan_status: ScanStatus::Idle,
            results: Vec::new(),
            current_scanner_index: 0,
            progress_message: String::new(),
            export_path: None,
            result_scroll: 0,
            result_tab: 0,
            started_at: None,
            finished_at: None,
            should_quit: false,
            export_cursor: 0,
            export_input: String::from("report.json"),
            show_help: false,
            tool_statuses: Vec::new(),
            tool_check_cursor: 0,
            install_progress: Vec::new(),
            install_scroll: 0,
        }
    }

    pub fn set_export_path(&mut self, path: String) {
        self.export_path = Some(path);
    }

    pub fn all_scanner_types() -> Vec<ScannerType> {
        vec![ScannerType::Nmap, ScannerType::Nuclei, ScannerType::Zap]
    }

    pub fn toggle_scanner(&mut self, index: usize) {
        if index < self.scanner_toggles.len() {
            self.scanner_toggles[index] = !self.scanner_toggles[index];
        }
    }

    pub fn get_selected_scanners(&self) -> Vec<ScannerType> {
        let all = Self::all_scanner_types();
        self.scanner_toggles
            .iter()
            .enumerate()
            .filter(|(_, &toggled)| toggled)
            .filter_map(|(i, _)| all.get(i).cloned())
            .collect()
    }

    pub fn start_scan(&mut self) {
        self.selected_scanners = self.get_selected_scanners();
        self.target = self.target_input.clone();
        self.screen = AppScreen::Scanning;
        self.scan_status = ScanStatus::Running;
        self.started_at = Some(Utc::now());
        self.current_scanner_index = 0;
        self.results.clear();
    }

    pub fn missing_tools(&self) -> Vec<&ToolStatus> {
        self.tool_statuses.iter().filter(|t| !t.installed).collect()
    }

    pub fn all_tools_installed(&self) -> bool {
        self.tool_statuses.iter().all(|t| t.installed)
    }
}
