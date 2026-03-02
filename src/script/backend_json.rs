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
use crate::traits::script_traits::ScriptBackend;
use crate::common::error::MgmError;
use crate::script::script_types::{RecordedOperation, SessionInfo, SessionScript};

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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::traits::script_traits::ScriptBackend;
    use crate::script::script_types::{RecordableObjectSpec, RecordedOperation, SessionInfo};
    use crate::hsm_operations::wrap::{WrapKeyType, WrapOpSpec, WrapType};
    use yubihsmrs::object::{
        ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType,
    };

    fn make_session_info() -> SessionInfo {
        SessionInfo {
            connector: "yhusb://serial=99999999".to_string(),
            auth_key_id: 1,
        }
    }

    fn make_spec() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0001,
            object_type: ObjectType::AsymmetricKey,
            label: "rsa-key".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignPkcs],
            delegated_capabilities: vec![],
        }
    }

    fn make_wrap_op_spec() -> WrapOpSpec {
        WrapOpSpec {
            wrapkey_id: 0x0010,
            wrapkey_type: WrapKeyType::Aes,
            wrap_type: WrapType::Object,
            include_ed_seed: false,
            aes_algorithm: Some(ObjectAlgorithm::Aes256CcmWrap),
            oaep_algorithm: None,
            mgf1_algorithm: None,
        }
    }

    fn make_diverse_operations() -> Vec<RecordedOperation> {
        vec![
            RecordedOperation::GenerateObject {
                spec: make_spec(),
                context: "asym".to_string(),
            },
            RecordedOperation::ImportObject {
                spec: make_spec(),
                value: "base64==".to_string(),
                context: "asym".to_string(),
            },
            RecordedOperation::DeleteObject {
                object_id: 0x0001,
                object_type: ObjectType::AsymmetricKey,
                context: "asym".to_string(),
            },
            RecordedOperation::CreateAuthKey {
                spec: RecordableObjectSpec {
                    id: 2,
                    object_type: ObjectType::AuthenticationKey,
                    label: "auth".to_string(),
                    algorithm: ObjectAlgorithm::Aes128YubicoAuthentication,
                    domains: vec![ObjectDomain::One],
                    capabilities: vec![ObjectCapability::PutAuthenticationKey],
                    delegated_capabilities: vec![ObjectCapability::SignPkcs],
                },
                credential: "pass".to_string(),
            },
            RecordedOperation::ExportWrapped {
                wrap_spec: make_wrap_op_spec(),
                objects: vec![ObjectHandle {
                    object_id: 1,
                    object_type: ObjectType::AsymmetricKey,
                }],
                destination_directory: "/tmp".to_string(),
            },
        ]
    }

    // ══════════════════════════════════════════════
    //  extension()
    // ══════════════════════════════════════════════

    #[test]
    fn test_extension() {
        assert_eq!(JsonBackend.extension(), "json");
    }

    // ══════════════════════════════════════════════
    //  write() creates a file
    // ══════════════════════════════════════════════

    #[test]
    fn test_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.json");

        JsonBackend.write(&path, &make_session_info(), &[]).unwrap();

        assert!(path.exists());
    }

    // ══════════════════════════════════════════════
    //  write() → read() round-trip
    // ══════════════════════════════════════════════

    #[test]
    fn test_roundtrip_empty_operations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        let info = make_session_info();

        JsonBackend.write(&path, &info, &[]).unwrap();
        let script = JsonBackend.read(&path).unwrap();

        assert_eq!(script.session.connector, info.connector);
        assert_eq!(script.session.auth_key_id, info.auth_key_id);
        assert!(script.operations.is_empty());
    }

    #[test]
    fn test_roundtrip_single_operation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("single.json");
        let info = make_session_info();
        let ops = vec![RecordedOperation::GenerateObject {
            spec: make_spec(),
            context: "asym".to_string(),
        }];

        JsonBackend.write(&path, &info, &ops).unwrap();
        let script = JsonBackend.read(&path).unwrap();

        assert_eq!(script.version, "1.0");
        assert_eq!(script.session.connector, info.connector);
        assert_eq!(script.session.auth_key_id, info.auth_key_id);
        assert_eq!(script.operations.len(), 1);
    }

    #[test]
    fn test_roundtrip_diverse_operations() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("diverse.json");
        let info = make_session_info();
        let ops = make_diverse_operations();

        JsonBackend.write(&path, &info, &ops).unwrap();
        let script = JsonBackend.read(&path).unwrap();

        assert_eq!(script.operations.len(), ops.len());
    }

    // ══════════════════════════════════════════════
    //  read() error cases
    // ══════════════════════════════════════════════

    #[test]
    fn test_read_invalid_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("invalid.json");
        fs::write(&path, "{ not valid json!!!").unwrap();
        assert!(JsonBackend.read(&path).is_err());
    }

    #[test]
    fn test_read_nonexistent_file() {
        let path = Path::new("/nonexistent/path/script.json");
        assert!(JsonBackend.read(path).is_err());
    }

    #[test]
    fn test_read_missing_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("partial.json");
        // Valid JSON but missing required fields
        fs::write(&path, r#"{"version": "1.0"}"#).unwrap();
        assert!(JsonBackend.read(&path).is_err());
    }

    // ══════════════════════════════════════════════
    //  Written file properties
    // ══════════════════════════════════════════════

    #[test]
    fn test_written_file_is_pretty_printed() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("pretty.json");
        JsonBackend
            .write(&path, &make_session_info(), &[])
            .unwrap();

        let content = fs::read_to_string(&path).unwrap();
        // Pretty-printed JSON has newlines and indentation
        assert!(content.contains('\n'), "Expected pretty-printed JSON");
        assert!(content.contains("  "), "Expected indentation");
    }

    #[test]
    fn test_written_file_contains_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("version.json");
        JsonBackend
            .write(&path, &make_session_info(), &[])
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"version\": \"1.0\""), "Content: {}", content);
    }
}