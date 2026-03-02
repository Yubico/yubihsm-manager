/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::cell::RefCell;
use std::path::PathBuf;
use crate::common::error::MgmError;
use crate::traits::script_traits::ScriptBackend;
use crate::script::script_types::{RecordedOperation, RedactMode, SessionInfo};

/// Accumulates recorded operations and writes them to a script file
pub struct SessionRecorder {
    session_into: SessionInfo,
    pub script_path: PathBuf,
    pub mode: RedactMode,
    backend: Box<dyn ScriptBackend>,
    operations: RefCell<Vec<RecordedOperation>>,
}

impl SessionRecorder {
    pub fn new(
        connector: String,
        auth_key_id: u16,
        script_path: String,
        mode: RedactMode,
        backend: Box<dyn ScriptBackend>) -> Self {
        Self {
            session_into: SessionInfo { connector, auth_key_id },
            script_path: PathBuf::from(script_path),
            mode,
            backend,
            operations: RefCell::new(Vec::new()),
        }
    }

    /// Record a single completed operation.
    pub fn record(&self, operation: RecordedOperation) -> Result<(), MgmError>{
        self.operations.borrow_mut().push(operation);
        self.flush()
    }

    /// Write the accumulated recording to the script file.
    fn flush(&self) -> Result<(), MgmError> {
        self.backend
           .write(&self.script_path, &self.session_into, &self.operations.borrow())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::script::backend_json::JsonBackend;
    use crate::script::script_types::{RecordableObjectSpec, RedactMode};
    use crate::traits::script_traits::ScriptBackend;
    use crate::script::script_recorder::SessionRecorder;
    use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};

    fn make_recorder(dir: &TempDir) -> SessionRecorder {
        let path = dir.path().join("recording.json");
        SessionRecorder::new(
            "yhusb://serial=11111111".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::Sensitive,
            Box::new(JsonBackend),
        )
    }

    fn make_generate_op() -> RecordedOperation {
        RecordedOperation::GenerateObject {
            spec: RecordableObjectSpec {
                id: 0x0042,
                object_type: ObjectType::AsymmetricKey,
                label: "test-key".to_string(),
                algorithm: ObjectAlgorithm::Rsa2048,
                domains: vec![ObjectDomain::One],
                capabilities: vec![ObjectCapability::SignPkcs],
                delegated_capabilities: vec![],
            },
            context: "asym".to_string(),
        }
    }

    fn make_delete_op(id: u16) -> RecordedOperation {
        RecordedOperation::DeleteObject {
            object_id: id,
            object_type: ObjectType::AsymmetricKey,
            context: "asym".to_string(),
        }
    }

    // ══════════════════════════════════════════════
    //  Construction
    // ══════════════════════════════════════════════

    #[test]
    fn test_new_recorder() {
        let dir = TempDir::new().unwrap();
        let rec = make_recorder(&dir);
        assert_eq!(rec.operation_count(), 0);
        assert_eq!(rec.mode, RedactMode::Sensitive);
    }

    // ══════════════════════════════════════════════
    //  record() increments count
    // ══════════════════════════════════════════════

    #[test]
    fn test_record_increments_count() {
        let dir = TempDir::new().unwrap();
        let rec = make_recorder(&dir);

        rec.record(make_generate_op()).unwrap();
        assert_eq!(rec.operation_count(), 1);

        rec.record(make_delete_op(0x0042)).unwrap();
        assert_eq!(rec.operation_count(), 2);
    }

    // ══════════════════════════════════════════════
    //  record() writes file to disk
    // ══════════════════════════════════════════════

    #[test]
    fn test_record_creates_file() {
        let dir = TempDir::new().unwrap();
        let rec = make_recorder(&dir);
        let path = rec.script_path.clone();

        rec.record(make_generate_op()).unwrap();
        assert!(path.exists());
    }

    // ══════════════════════════════════════════════
    //  Multiple records → file has all operations
    // ══════════════════════════════════════════════

    #[test]
    fn test_multiple_records_all_present() {
        let dir = TempDir::new().unwrap();
        let rec = make_recorder(&dir);
        let path = rec.script_path.clone();

        rec.record(make_generate_op()).unwrap();
        rec.record(make_delete_op(0x0042)).unwrap();
        rec.record(make_delete_op(0x0043)).unwrap();

        // Read back with JsonBackend
        let script = JsonBackend.read(&path).unwrap();
        assert_eq!(script.operations.len(), 3);
    }

    // ══════════════════════════════════════════════
    //  Drop: does not create file when 0 operations
    // ══════════════════════════════════════════════

    #[test]
    fn test_drop_no_file_when_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty_drop.json");
        {
            let _rec = SessionRecorder::new(
                "yhusb://serial=00000000".to_string(),
                1,
                path.to_str().unwrap().to_string(),
                RedactMode::Sensitive,
                Box::new(JsonBackend),
            );
            // rec is dropped here with 0 operations
        }
        assert!(!path.exists(), "File should not be created for 0 operations");
    }
}