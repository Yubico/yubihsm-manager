use std::fs;
use std::path::PathBuf;
use chrono::Utc;
use crate::script::types::{RecordedOperation, SessionScript};

/// Accumulates recorded operations and writes them to a JSON file on flush.
pub struct SessionRecorder {
    operations: Vec<RecordedOperation>,
    output_path: PathBuf,
    connector: String,
    auth_key_id: u16,
}

impl SessionRecorder {
    pub fn new(output_path: PathBuf, connector: String, auth_key_id: u16) -> Self {
        Self {
            operations: Vec::new(),
            output_path,
            connector,
            auth_key_id,
        }
    }

    /// Record a single completed operation.
    pub fn record(&mut self, operation: RecordedOperation) {
        self.operations.push(operation);
    }

    /// Write the accumulated recording to the JSON file.
    pub fn flush(&self) -> Result<(), std::io::Error> {
        let script = SessionScript {
            version: "1.0".to_string(),
            recorded_at: Utc::now().to_rfc3339(),
            session: crate::script::types::SessionInfo {
                connector: self.connector.clone(),
                auth_key_id: self.auth_key_id,
                password: "<PASSWORD>".to_string(),
            },
            operations: self.operations.clone(),
        };

        let json = serde_json::to_string_pretty(&script)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        fs::write(&self.output_path, json)
    }

    /// Returns how many operations have been recorded so far.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
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