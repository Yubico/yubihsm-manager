use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use chrono::Local;
use crate::script::script_common::{RecordedOperation, RedactMode, SessionInfo, SessionScript};

/// Accumulates recorded operations and writes them to a JSON file on flush.
pub struct SessionRecorder {
    connector: String,
    auth_key_id: u16,
    pub script_path: PathBuf,
    pub mode: RedactMode,
    operations: RefCell<Vec<RecordedOperation>>,
}

impl SessionRecorder {
    pub fn new(connector: String, auth_key_id: u16, script_path: String, mode: RedactMode) -> Self {
        Self {
            connector,
            auth_key_id,
            script_path: PathBuf::from(script_path),
            mode,
            operations: RefCell::new(Vec::new()),
        }
    }

    /// Record a single completed operation.
    pub fn record(&self, operation: RecordedOperation) -> Result<(), std::io::Error>{
        self.operations.borrow_mut().push(operation);
        self.flush()
    }

    /// Write the accumulated recording to the JSON file.
    fn flush(&self) -> Result<(), std::io::Error> {
        let script = SessionScript {
            version: "1.0".to_string(),
            recorded_at: Local::now().format("%Y%m%d-%H:%M:%S").to_string(),
            session: SessionInfo {
                connector: self.connector.clone(),
                auth_key_id: self.auth_key_id,
            },
            operations: self.operations.borrow().clone(),
        };

        let json = serde_json::to_string_pretty(&script)?;

        fs::write(&self.script_path, json)
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