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
use crate::hsm_operations::error::MgmError;
use crate::traits::script_backend::ScriptBackend;
use crate::script::script_common::{RecordedOperation, RedactMode, SessionInfo};

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