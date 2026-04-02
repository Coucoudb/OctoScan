use chrono::Utc;
use log::{Level, Log, Metadata, Record};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOGGER: FileLogger = FileLogger {
    path: Mutex::new(None),
};

struct FileLogger {
    path: Mutex<Option<PathBuf>>,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let guard = self.path.lock().unwrap();
        if let Some(ref path) = *guard {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
                let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S");
                let _ = writeln!(
                    file,
                    "[{}] [{}] {}",
                    timestamp,
                    record.level(),
                    record.args()
                );
            }
        }
    }

    fn flush(&self) {}
}

/// Initialize the file logger. Returns the path to the log file.
pub fn init() -> PathBuf {
    let log_dir = get_log_dir();
    let _ = fs::create_dir_all(&log_dir);

    let log_file = log_dir.join(format!(
        "octoscan_{}.log",
        Utc::now().format("%Y%m%d_%H%M%S")
    ));

    {
        let mut guard = LOGGER.path.lock().unwrap();
        *guard = Some(log_file.clone());
    }

    let _ = log::set_logger(&LOGGER);
    log::set_max_level(log::LevelFilter::Debug);

    // Write header
    log::info!("OctoScan v{} started", env!("CARGO_PKG_VERSION"));
    log::info!("Log file: {}", log_file.display());
    log::info!("OS: {}", std::env::consts::OS);

    log_file
}

fn get_log_dir() -> PathBuf {
    if let Some(data_dir) = dirs_log() {
        data_dir.join("octoscan").join("logs")
    } else {
        PathBuf::from("logs")
    }
}

fn dirs_log() -> Option<PathBuf> {
    // Use platform-appropriate log directory
    #[cfg(target_os = "windows")]
    {
        std::env::var("LOCALAPPDATA").ok().map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Logs"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".local").join("share"))
    }
}
