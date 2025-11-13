pub struct RustLogger;

impl RustLogger {
    pub fn debug(&self, network_id: u32, message: &str) {
        crate::forward_log_by_network(network_id, 0, message);
    }

    pub fn info(&self, network_id: u32, message: &str) {
        crate::forward_log_by_network(network_id, 1, message);
    }

    pub fn warn(&self, network_id: u32, message: &str) {
        crate::forward_log_by_network(network_id, 2, message);
    }

    pub fn error(&self, network_id: u32, message: &str) {
        crate::forward_log_by_network(network_id, 3, message);
    }
}

#[allow(non_upper_case_globals)]
pub static rustLogger: RustLogger = RustLogger;
