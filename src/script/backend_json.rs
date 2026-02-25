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

use std::fs;
use std::path::Path;
use crate::traits::script_backend::ScriptBackend;
use crate::hsm_operations::error::MgmError;
use crate::script::script_common::{RecordedOperation, SessionInfo, SessionScript};

pub struct JsonBackend;

impl ScriptBackend for JsonBackend {
    fn extension(&self) -> &'static str {
        "json"
    }

    fn write(
        &self,
        path: &Path,
        session_info: &SessionInfo,
        operations: &[RecordedOperation],
    ) -> Result<(), MgmError> {
        let script = SessionScript {
            version: "1.0".to_string(),
            recorded_at: chrono::Local::now().format("%Y%m%d-%H:%M:%S").to_string(),
            session: session_info.clone(),
            operations: operations.to_vec(),
        };
        let json = serde_json::to_string_pretty(&script)
            .map_err(|e| MgmError::Error(format!("JSON serialization failed: {}", e)))?;
        fs::write(path, json)?;
        Ok(())
    }

    fn read(
        &self,
        path: &Path,
    ) -> Result<SessionScript, MgmError> {
        let content = fs::read_to_string(path)?;
        let script: SessionScript = serde_json::from_str(&content)
            .map_err(|e| MgmError::Error(format!("Failed to parse script: {}", e)))?;
        Ok(script)
    }
}