use crate::installer::{InstallProgress, ToolStatus};
use crate::profiles::Profile;
use crate::scanners::{ScanResult, ScannerType};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppScreen {
    Home,
    TargetInput,
    ProfileSelect,
    ScannerSelect,
    ScannerArgs,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerRunStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

pub struct App {
    pub id: Uuid,
    pub screen: AppScreen,
    pub target: String,
    pub target_input: String,
    pub selected_scanners: Vec<ScannerType>,
    pub scanner_cursor: usize,
    pub scanner_toggles: [bool; 9],
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
    pub install_progress: Vec<InstallProgress>,
    pub install_scroll: u16,
    // Logging
    pub log_path: Option<String>,
    // Per-scanner status tracking for parallel execution
    pub scanner_statuses: Vec<(ScannerType, ScannerRunStatus)>,
    pub spin_tick: usize,
    // Custom scanner arguments
    pub scanner_args: HashMap<ScannerType, Vec<String>>,
    pub scanner_args_input: String,
    pub scanner_args_cursor: usize,
    // Profile selection
    pub available_profiles: Vec<Profile>,
    pub profile_cursor: usize,
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
            scanner_toggles: [false; 9],
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
            install_progress: Vec::new(),
            install_scroll: 0,
            log_path: None,
            scanner_statuses: Vec::new(),
            spin_tick: 0,
            scanner_args: HashMap::new(),
            scanner_args_input: String::new(),
            scanner_args_cursor: 0,
            available_profiles: crate::profiles::all_profiles(),
            profile_cursor: 0,
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
            scanner_toggles: [false; 9],
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
            install_progress: Vec::new(),
            install_scroll: 0,
            log_path: None,
            scanner_statuses: Vec::new(),
            spin_tick: 0,
            scanner_args: HashMap::new(),
            scanner_args_input: String::new(),
            scanner_args_cursor: 0,
            available_profiles: crate::profiles::all_profiles(),
            profile_cursor: 0,
        }
    }

    pub fn set_export_path(&mut self, path: String) {
        self.export_path = Some(path);
    }

    pub fn all_scanner_types() -> Vec<ScannerType> {
        vec![
            // Reconnaissance
            ScannerType::Feroxbuster,
            ScannerType::Httpx,
            ScannerType::Nmap,
            ScannerType::Subfinder,
            // Vulnerability Scanning
            ScannerType::Nuclei,
            // Web Application
            ScannerType::Wpscan,
            ScannerType::Zap,
            // Exploitation
            ScannerType::Sqlmap,
            // Brute-force
            ScannerType::Hydra,
        ]
    }

    pub fn toggle_scanner(&mut self, index: usize) {
        if index < self.scanner_toggles.len() {
            self.scanner_toggles[index] = !self.scanner_toggles[index];
        }
    }

    /// Apply a profile by toggling the scanners it contains
    pub fn apply_profile(&mut self, profile: &crate::profiles::Profile) {
        let all = Self::all_scanner_types();
        for (i, scanner) in all.iter().enumerate() {
            self.scanner_toggles[i] = profile.scanners.contains(scanner);
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

    pub fn sqlmap_selected(&self) -> bool {
        self.selected_scanners.contains(&ScannerType::Sqlmap)
    }

    pub fn hydra_selected(&self) -> bool {
        self.selected_scanners.contains(&ScannerType::Hydra)
    }

    /// Get scanners to run in parallel (excludes Sqlmap and Hydra which are conditional)
    pub fn parallel_scanners(&self) -> Vec<ScannerType> {
        self.selected_scanners
            .iter()
            .filter(|s| **s != ScannerType::Sqlmap && **s != ScannerType::Hydra)
            .cloned()
            .collect()
    }

    pub fn missing_tools(&self) -> Vec<&ToolStatus> {
        self.tool_statuses.iter().filter(|t| !t.installed).collect()
    }

    pub fn all_tools_installed(&self) -> bool {
        self.tool_statuses.iter().all(|t| t.installed)
    }

    pub fn init_scanner_statuses(&mut self) {
        self.scanner_statuses = self
            .selected_scanners
            .iter()
            .map(|s| (s.clone(), ScannerRunStatus::Pending))
            .collect();
    }

    pub fn update_scanner_status(&mut self, scanner: &ScannerType, status: ScannerRunStatus) {
        if let Some(entry) = self.scanner_statuses.iter_mut().find(|(s, _)| s == scanner) {
            entry.1 = status;
        }
    }
}
