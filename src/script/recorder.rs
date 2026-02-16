use std::cell::RefCell;
use std::fs;
use std::path::Path;
use chrono::Local;
use crate::script::types::{RecordedOperation, SessionScript};

/// Accumulates recorded operations and writes them to a JSON file on flush.
pub struct SessionRecorder {
    operations: RefCell<Vec<RecordedOperation>>,
    connector: String,
    auth_key_id: u16,
}

impl SessionRecorder {
    pub fn new(connector: String, auth_key_id: u16) -> Self {
        Self {
            operations: RefCell::new(Vec::new()),
            connector,
            auth_key_id,
        }
    }

    /// Record a single completed operation.
    pub fn record(&self, operation: RecordedOperation) {
        self.operations.borrow_mut().push(operation);
    }

    /// Write the accumulated recording to the JSON file.
    pub fn flush(&self) -> Result<String, std::io::Error> {
        let timestamp = Local::now().format("%Y%m%d-%H:%M:%S").to_string();
        let script = SessionScript {
            version: "1.0".to_string(),
            recorded_at: timestamp.clone(),
            session: crate::script::types::SessionInfo {
                connector: self.connector.clone(),
                auth_key_id: self.auth_key_id,
                password: "<PASSWORD>".to_string(),
            },
            operations: self.operations.borrow().clone(),
        };

        let json = serde_json::to_string_pretty(&script)?;

        let filename = format!("./yubihsm-manager-script-{}.json", timestamp);
        fs::write(Path::new(&filename), json)?;
        Ok(filename)
    }

    /// Returns how many operations have been recorded so far.
    pub fn operation_count(&self) -> usize {
        self.operations.borrow().len()
    }
}

impl Drop for SessionRecorder {
    fn drop(&mut self) {
        // Best-effort flush on drop — ensures recording is written even on
        // unexpected exits (panics, etc.), as long as destructors run.
        if self.operation_count() > 0 {
            let _ = self.flush();
        }
    }
}