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

use std::path::Path;
use crate::script::script_common::SessionScript;
use crate::hsm_operations::error::MgmError;
use crate::script::script_common::{RecordedOperation, SessionInfo};

/// A script backend knows how to read/write a particular script format.
pub trait ScriptBackend {

    /// File extension this backend produces (e.g. "json", "sh").
    fn extension(&self) -> &'static str;

    /// Serialize a full session script to a file.
    fn write(
        &self,
        path: &Path,
        session_info: &SessionInfo,
        operations: &[RecordedOperation],
    ) -> Result<(), MgmError>;

    /// Deserialize a script file back into the canonical model.
    /// Returns `MgmErr` for formats that are write-only (e.g. bash).
    fn read(
        &self,
        path: &Path,
    ) -> Result<SessionScript, MgmError>;

}