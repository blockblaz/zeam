use chrono::{Datelike, Local, Timelike};
use std::fmt::Write;
use std::sync::Mutex;

const RESET: &str = "\x1b[0m";
const ERR_COLOR: &str = "\x1b[31m"; // Red
const WARN_COLOR: &str = "\x1b[33m"; // Yellow
const INFO_COLOR: &str = "\x1b[32m"; // Green
const DEBUG_COLOR: &str = "\x1b[36m"; // Cyan
const TIMESTAMP_COLOR: &str = "\x1b[90m"; // Bright black
const SCOPE_COLOR: &str = "\x1b[35m"; // Magenta
const MODULE_COLOR: &str = "\x1b[94m"; // Bright blue

// Lock for thread-safe logging
static LOG_MUTEX: Mutex<()> = Mutex::new(());

pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_text(&self) -> &str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    fn color(&self) -> &str {
        match self {
            LogLevel::Debug => DEBUG_COLOR,
            LogLevel::Info => INFO_COLOR,
            LogLevel::Warn => WARN_COLOR,
            LogLevel::Error => ERR_COLOR,
        }
    }
}

fn get_scope_prefix(network_id: u32) -> String {
    // Map network_id to zeam scope
    // Based on the code in pkgs/cli/src/main.zig:
    // network_id 0 uses logger1_config (.n1) -> zeam-n1
    // network_id 1 uses logger2_config (.n2) -> zeam-n2
    let scope_suffix = match network_id {
        0 => "zeam-n1",
        1 => "zeam-n2",
        2 => "zeam-n3",
        _ => "zeam-default",
    };
    format!("({}):", scope_suffix)
}

fn get_formatted_timestamp() -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let now = Local::now();
    let month_str = MONTHS.get(now.month0() as usize).unwrap_or(&"???");

    format!(
        "{}-{:02} {:02}:{:02}:{:02}.{:03}",
        month_str,
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.nanosecond() / 1_000_000
    )
}

fn log_with_level(level: LogLevel, network_id: u32, module: Option<&str>, message: &str) {
    let _lock = LOG_MUTEX.lock().expect("LOG_MUTEX poisoned");

    let timestamp = get_formatted_timestamp();
    let scope_prefix = get_scope_prefix(network_id);

    let mut output = String::new();

    // Build the log message with colors
    write!(
        output,
        "{}{}{} {}[{}{}]{}{} {} ",
        TIMESTAMP_COLOR,
        timestamp,
        RESET,
        level.color(),
        level.as_text(),
        RESET,
        SCOPE_COLOR,
        scope_prefix,
        RESET
    )
    .expect("Failed to format log header");

    // Add module tag if provided
    if let Some(module) = module {
        write!(output, "{}[{}]{} ", MODULE_COLOR, module, RESET)
            .expect("Failed to format module tag");
    }

    // Add the actual message
    write!(output, "{}", message).expect("Failed to format log message");

    // Write to stderr (matching Zig behavior)
    eprintln!("{}", output);
}

pub fn log_debug(network_id: u32, message: &str) {
    log_with_level(LogLevel::Debug, network_id, None, message);
}

pub fn log_info(network_id: u32, message: &str) {
    log_with_level(LogLevel::Info, network_id, None, message);
}

pub fn log_warn(network_id: u32, message: &str) {
    log_with_level(LogLevel::Warn, network_id, None, message);
}

pub fn log_error(network_id: u32, message: &str) {
    log_with_level(LogLevel::Error, network_id, None, message);
}

pub fn log_debug_module(network_id: u32, module: &str, message: &str) {
    log_with_level(LogLevel::Debug, network_id, Some(module), message);
}

pub fn log_info_module(network_id: u32, module: &str, message: &str) {
    log_with_level(LogLevel::Info, network_id, Some(module), message);
}

pub fn log_warn_module(network_id: u32, module: &str, message: &str) {
    log_with_level(LogLevel::Warn, network_id, Some(module), message);
}

pub fn log_error_module(network_id: u32, module: &str, message: &str) {
    log_with_level(LogLevel::Error, network_id, Some(module), message);
}
