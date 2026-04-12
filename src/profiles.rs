use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scanners::ScannerType;

// ─── Built-in profiles ──────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub scanners: Vec<ScannerType>,
}

pub fn builtin_profiles() -> Vec<Profile> {
    vec![
        Profile {
            name: "quick".to_string(),
            description: "Fast port scan (Nmap only)".to_string(),
            scanners: vec![ScannerType::Nmap],
        },
        Profile {
            name: "web".to_string(),
            description: "Web application audit (Nmap, Nuclei, Feroxbuster, ZAP)".to_string(),
            scanners: vec![
                ScannerType::Nmap,
                ScannerType::Nuclei,
                ScannerType::Feroxbuster,
                ScannerType::Zap,
            ],
        },
        Profile {
            name: "recon".to_string(),
            description: "Reconnaissance (Subfinder, httpx, Nmap)".to_string(),
            scanners: vec![
                ScannerType::Subfinder,
                ScannerType::Httpx,
                ScannerType::Nmap,
            ],
        },
        Profile {
            name: "full".to_string(),
            description: "All scanners".to_string(),
            scanners: vec![
                ScannerType::Nmap,
                ScannerType::Nuclei,
                ScannerType::Zap,
                ScannerType::Feroxbuster,
                ScannerType::Sqlmap,
                ScannerType::Subfinder,
                ScannerType::Httpx,
                ScannerType::Wpscan,
                ScannerType::Hydra,
            ],
        },
    ]
}

// ─── Config file (user-defined profiles) ────────

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProfileConfig {
    pub description: Option<String>,
    pub scanners: Vec<String>,
}

/// Default config directory: ~/.config/octoscan/ (Linux/macOS) or %APPDATA%/octoscan/ (Windows)
pub fn config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("octoscan"))
}

/// Default config file path
pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.toml"))
}

/// Load config from the default path, returning None if the file doesn't exist
pub fn load_config() -> Option<Config> {
    let path = config_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}

/// Resolve user-defined profiles from config into Profile structs.
/// Invalid scanner names are silently skipped.
fn resolve_user_profiles(config: &Config) -> Vec<Profile> {
    config
        .profiles
        .iter()
        .filter_map(|(name, pc)| {
            let scanners: Vec<ScannerType> =
                pc.scanners.iter().filter_map(|s| s.parse().ok()).collect();
            if scanners.is_empty() {
                return None;
            }
            Some(Profile {
                name: name.clone(),
                description: pc
                    .description
                    .clone()
                    .unwrap_or_else(|| format!("Custom profile: {}", name)),
                scanners,
            })
        })
        .collect()
}

/// Return all available profiles: built-in + user-defined (from config).
/// User profiles with the same name as a built-in profile override it.
pub fn all_profiles() -> Vec<Profile> {
    let mut profiles = builtin_profiles();

    if let Some(config) = load_config() {
        let user = resolve_user_profiles(&config);
        for up in user {
            if let Some(existing) = profiles.iter_mut().find(|p| p.name == up.name) {
                *existing = up;
            } else {
                profiles.push(up);
            }
        }
    }

    profiles
}

/// Find a profile by name (case-insensitive) from all available profiles.
pub fn find_profile(name: &str) -> Option<Profile> {
    let lower = name.to_lowercase();
    all_profiles().into_iter().find(|p| p.name == lower)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_quick_profile() {
        let profiles = builtin_profiles();
        let quick = profiles.iter().find(|p| p.name == "quick").unwrap();
        assert_eq!(quick.scanners, vec![ScannerType::Nmap]);
    }

    #[test]
    fn builtin_web_profile() {
        let profiles = builtin_profiles();
        let web = profiles.iter().find(|p| p.name == "web").unwrap();
        assert_eq!(web.scanners.len(), 4);
        assert!(web.scanners.contains(&ScannerType::Nmap));
        assert!(web.scanners.contains(&ScannerType::Nuclei));
        assert!(web.scanners.contains(&ScannerType::Feroxbuster));
        assert!(web.scanners.contains(&ScannerType::Zap));
    }

    #[test]
    fn builtin_recon_profile() {
        let profiles = builtin_profiles();
        let recon = profiles.iter().find(|p| p.name == "recon").unwrap();
        assert_eq!(recon.scanners.len(), 3);
        assert!(recon.scanners.contains(&ScannerType::Subfinder));
        assert!(recon.scanners.contains(&ScannerType::Httpx));
        assert!(recon.scanners.contains(&ScannerType::Nmap));
    }

    #[test]
    fn builtin_full_profile_has_all_scanners() {
        let profiles = builtin_profiles();
        let full = profiles.iter().find(|p| p.name == "full").unwrap();
        assert_eq!(full.scanners.len(), 9);
    }

    #[test]
    fn find_profile_case_insensitive() {
        // This tests against builtins only (no config file)
        let p = find_profile("QUICK");
        assert!(p.is_some());
        assert_eq!(p.unwrap().name, "quick");
    }

    #[test]
    fn find_profile_unknown_returns_none() {
        let p = find_profile("nonexistent");
        assert!(p.is_none());
    }

    #[test]
    fn resolve_user_profiles_valid() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "stealthy".to_string(),
            ProfileConfig {
                description: Some("Low-noise scan".to_string()),
                scanners: vec!["nmap".to_string(), "subfinder".to_string()],
            },
        );
        let config = Config { profiles };
        let resolved = resolve_user_profiles(&config);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].name, "stealthy");
        assert_eq!(resolved[0].scanners.len(), 2);
    }

    #[test]
    fn resolve_user_profiles_skips_invalid_scanners() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "mixed".to_string(),
            ProfileConfig {
                description: None,
                scanners: vec![
                    "nmap".to_string(),
                    "notreal".to_string(),
                    "nuclei".to_string(),
                ],
            },
        );
        let config = Config { profiles };
        let resolved = resolve_user_profiles(&config);
        assert_eq!(resolved[0].scanners.len(), 2);
    }

    #[test]
    fn resolve_user_profiles_drops_empty() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "empty".to_string(),
            ProfileConfig {
                description: None,
                scanners: vec!["notreal".to_string()],
            },
        );
        let config = Config { profiles };
        let resolved = resolve_user_profiles(&config);
        assert!(resolved.is_empty());
    }
}
