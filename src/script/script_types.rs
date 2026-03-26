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

use std::fmt;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use crate::common::types::NewObjectSpec;
use crate::hsm_operations::wrap::WrapOpSpec;

pub const PROMPT: &str = "<PROMPT>";

#[derive(Clone, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum MaskLevel {
    #[default]
    Sensitive,
    All,
    None,
}

impl Display for MaskLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MaskLevel::Sensitive => write!(f, "sensitive"),
            MaskLevel::All => write!(f, "all"),
            MaskLevel::None => write!(f, "none"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionScript {
    pub version: String,
    pub recorded_at: String,
    pub session: SessionInfo,
    pub operations: Vec<RecordedOperation>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionInfo {
    pub connector: String,
    pub auth_key_id: u16,
}

/// Serde-friendly mirror of NewObjectSpec using real yubihsmrs types.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecordableObjectSpec {
    pub id: u16,
    pub object_type: ObjectType,
    pub label: String,
    pub algorithm: ObjectAlgorithm,
    pub domains: Vec<ObjectDomain>,
    pub capabilities: Vec<ObjectCapability>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub delegated_capabilities: Vec<ObjectCapability>,
}

impl From<&NewObjectSpec> for RecordableObjectSpec {
    fn from(spec: &NewObjectSpec) -> Self {
        Self {
            id: spec.id,
            object_type: spec.object_type,
            label: spec.label.clone(),
            algorithm: spec.algorithm,
            domains: spec.domains.clone(),
            capabilities: spec.capabilities.clone(),
            delegated_capabilities: spec.delegated_capabilities.clone(),
        }
    }
}

impl From<&RecordableObjectSpec> for NewObjectSpec {
    fn from(spec: &RecordableObjectSpec) -> Self {
        NewObjectSpec {
            id: spec.id,
            object_type: spec.object_type,
            label: spec.label.clone(),
            algorithm: spec.algorithm,
            domains: spec.domains.clone(),
            capabilities: spec.capabilities.clone(),
            delegated_capabilities: spec.delegated_capabilities.clone(),
            data: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "operation", content = "params")]
pub enum RecordedOperation {

    // Key management (generate / import / delete)

    GenerateObject {
        spec: RecordableObjectSpec,
        context: String,
    },

    ImportObject {
        spec: RecordableObjectSpec,
        value: String,
        context: String,
    },

    ImportWrapKey {
        spec: RecordableObjectSpec,
        value: String,
        n_threshold: u8,
        n_shares: u8,
    },

    DeleteObject {
        object_id: u16,
        object_type: ObjectType,
        context: String,
    },

    // ── Authentication key management ──

    CreateAuthKey {
        spec: RecordableObjectSpec,
        credential: String,
    },

    // ── Wrap key management ──

    ExportWrapped {
        wrap_spec: WrapOpSpec,
        objects: Vec<ObjectHandle>,
        destination_directory: String,
    },

    ImportWrapped {
        wrap_spec: WrapOpSpec,
        wrapped_filepath: String,
        new_key_spec: Option<RecordableObjectSpec>,
    },

    BackupDevice {
        wrap_spec: WrapOpSpec,
        objects: Vec<ObjectHandle>,
        destination_directory: String,
    },

    RestoreDevice {
        wrap_spec: WrapOpSpec,
        source_directory: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubihsmrs::object::{
        ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType,
    };
    use crate::hsm_operations::wrap::{WrapKeyType, WrapOpSpec, WrapType};

    // ── Helper: build test data structures ──

    fn make_recordable_spec() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0042,
            object_type: ObjectType::AsymmetricKey,
            label: "test-key".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One, ObjectDomain::Three],
            capabilities: vec![ObjectCapability::SignPkcs, ObjectCapability::ExportableUnderWrap],
            delegated_capabilities: vec![],
        }
    }

    fn make_recordable_spec_with_delegated() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0001,
            object_type: ObjectType::AuthenticationKey,
            label: "auth-key".to_string(),
            algorithm: ObjectAlgorithm::Aes128YubicoAuthentication,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::PutAuthenticationKey],
            delegated_capabilities: vec![ObjectCapability::SignPkcs, ObjectCapability::SignPss],
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

    fn make_session_info() -> SessionInfo {
        SessionInfo {
            connector: "yhusb://serial=12345678".to_string(),
            auth_key_id: 1,
        }
    }

    // ══════════════════════════════════════════════
    //  MaskLevel
    // ══════════════════════════════════════════════

    #[test]
    fn test_mask_level_default() {
        assert_eq!(MaskLevel::default(), MaskLevel::Sensitive);
    }

    // ══════════════════════════════════════════════
    //  RecordableObjectSpec ↔ NewObjectSpec conversions
    // ══════════════════════════════════════════════

    #[test]
    fn test_from_new_object_spec() {
        let new_spec = NewObjectSpec {
            id: 0x0042,
            object_type: ObjectType::AsymmetricKey,
            label: "test-key".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignPkcs],
            delegated_capabilities: vec![ObjectCapability::ExportWrapped],
            data: vec![vec![0xDE, 0xAD]], // data is NOT carried over
        };

        let rec: RecordableObjectSpec = (&new_spec).into();
        assert_eq!(rec.id, new_spec.id);
        assert_eq!(rec.object_type, new_spec.object_type);
        assert_eq!(rec.label, new_spec.label);
        assert_eq!(rec.algorithm, new_spec.algorithm);
        assert_eq!(rec.domains, new_spec.domains);
        assert_eq!(rec.capabilities, new_spec.capabilities);
        assert_eq!(rec.delegated_capabilities, new_spec.delegated_capabilities);
    }

    #[test]
    fn test_from_recordable_to_new_spec() {
        let rec = make_recordable_spec();
        let new_spec: NewObjectSpec = NewObjectSpec::from(&rec);
        assert_eq!(new_spec.id, rec.id);
        assert_eq!(new_spec.object_type, rec.object_type);
        assert_eq!(new_spec.label, rec.label);
        assert_eq!(new_spec.algorithm, rec.algorithm);
        assert_eq!(new_spec.domains, rec.domains);
        assert_eq!(new_spec.capabilities, rec.capabilities);
        assert_eq!(new_spec.delegated_capabilities, rec.delegated_capabilities);
        // data is always empty when converting from RecordableObjectSpec
        assert!(new_spec.data.is_empty());
    }

    #[test]
    fn test_roundtrip_new_recordable_new() {
        let original = NewObjectSpec {
            id: 0x00FF,
            object_type: ObjectType::SymmetricKey,
            label: "sym".to_string(),
            algorithm: ObjectAlgorithm::Aes256,
            domains: vec![ObjectDomain::Two],
            capabilities: vec![ObjectCapability::EncryptCbc],
            delegated_capabilities: vec![],
            data: vec![],
        };
        let rec: RecordableObjectSpec = (&original).into();
        let recovered: NewObjectSpec = (&rec).into();
        assert_eq!(recovered.id, original.id);
        assert_eq!(recovered.object_type, original.object_type);
        assert_eq!(recovered.label, original.label);
        assert_eq!(recovered.algorithm, original.algorithm);
        assert_eq!(recovered.domains, original.domains);
        assert_eq!(recovered.capabilities, original.capabilities);
        assert_eq!(recovered.delegated_capabilities, original.delegated_capabilities);
    }

    // ══════���═══════════════════════════════════════
    //  Serde: individual RecordedOperation variants
    // ══════════════════════════════════════════════

    fn json_roundtrip(op: &RecordedOperation) -> RecordedOperation {
        let json = serde_json::to_string_pretty(op).expect("serialize failed");
        serde_json::from_str(&json).expect("deserialize failed")
    }

    #[test]
    fn test_serde_generate_object() {
        let op = RecordedOperation::GenerateObject {
            spec: make_recordable_spec(),
            context: "asym".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("\"operation\":\"GenerateObject\""));
        assert!(json.contains("\"params\""));
        let rec_op: RecordedOperation = serde_json::from_str(&json).unwrap();
        assert!(matches!(rec_op, RecordedOperation::GenerateObject { .. }));
    }

    #[test]
    fn test_serde_import_object() {
        let op = RecordedOperation::ImportObject {
            spec: make_recordable_spec(),
            value: "base64data==".to_string(),
            context: "asym".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::ImportObject { value, .. } = rt {
            assert_eq!(value, "base64data==");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_import_wrap_key() {
        let op = RecordedOperation::ImportWrapKey {
            spec: make_recordable_spec(),
            value: "keydata".to_string(),
            n_threshold: 2,
            n_shares: 3,
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::ImportWrapKey { n_threshold, n_shares, .. } = rt {
            assert_eq!(n_threshold, 2);
            assert_eq!(n_shares, 3);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_delete_object() {
        let op = RecordedOperation::DeleteObject {
            object_id: 0x1234,
            object_type: ObjectType::AsymmetricKey,
            context: "asym".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::DeleteObject { object_id, object_type, context } = rt {
            assert_eq!(object_id, 0x1234);
            assert_eq!(object_type, ObjectType::AsymmetricKey);
            assert_eq!(context, "asym");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_create_auth_key() {
        let authkey = make_recordable_spec_with_delegated();
        let op = RecordedOperation::CreateAuthKey {
            spec: authkey.clone(),
            credential: "password123".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::CreateAuthKey { spec, credential } = rt {
            assert_eq!(credential, "password123");
            assert_eq!(spec.delegated_capabilities.len(), authkey.delegated_capabilities.len());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_export_wrapped() {
        let op = RecordedOperation::ExportWrapped {
            wrap_spec: make_wrap_op_spec(),
            objects: vec![
                ObjectHandle { object_id: 0x0001, object_type: ObjectType::AsymmetricKey },
                ObjectHandle { object_id: 0x0002, object_type: ObjectType::SymmetricKey },
            ],
            destination_directory: "/tmp/export".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::ExportWrapped { objects, destination_directory, .. } = rt {
            assert_eq!(objects.len(), 2);
            assert_eq!(destination_directory, "/tmp/export");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_import_wrapped_with_spec() {
        let key_spec = make_recordable_spec();
        let op = RecordedOperation::ImportWrapped {
            wrap_spec: make_wrap_op_spec(),
            wrapped_filepath: "/tmp/wrapped.bin".to_string(),
            new_key_spec: Some(key_spec.clone()),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::ImportWrapped { new_key_spec, .. } = rt {
            assert!(new_key_spec.is_some());
            assert_eq!(new_key_spec.unwrap().id, key_spec.id);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_import_wrapped_without_spec() {
        let op = RecordedOperation::ImportWrapped {
            wrap_spec: make_wrap_op_spec(),
            wrapped_filepath: "/tmp/wrapped.bin".to_string(),
            new_key_spec: None,
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::ImportWrapped { new_key_spec, .. } = rt {
            assert!(new_key_spec.is_none());
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_backup_device() {
        let op = RecordedOperation::BackupDevice {
            wrap_spec: make_wrap_op_spec(),
            objects: vec![
                ObjectHandle { object_id: 1, object_type: ObjectType::AsymmetricKey },
            ],
            destination_directory: "/backup".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::BackupDevice { objects, destination_directory, .. } = rt {
            assert_eq!(objects.len(), 1);
            assert_eq!(destination_directory, "/backup");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_serde_restore_device() {
        let op = RecordedOperation::RestoreDevice {
            wrap_spec: make_wrap_op_spec(),
            source_directory: "/restore".to_string(),
        };
        let rt = json_roundtrip(&op);
        if let RecordedOperation::RestoreDevice { source_directory, .. } = rt {
            assert_eq!(source_directory, "/restore");
        } else {
            panic!("wrong variant");
        }
    }

    // ══════════════════════════════════════════════
    //  Serde: tagged enum format verification
    // ══════════════════════════════════════════════

    #[test]
    fn test_serde_tagged_format() {
        let op = RecordedOperation::GenerateObject {
            spec: make_recordable_spec(),
            context: "asym".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        // Internally-tagged: should have "operation" and "params" keys
        assert!(json.contains("\"operation\""), "JSON: {}", json);
        assert!(json.contains("\"params\""), "JSON: {}", json);
    }

    // ══════════════════════════════════════════════
    //  Serde: delegated_capabilities skip_serializing_if empty
    // ══════════════════════════════════════════════

    #[test]
    fn test_serde_empty_delegated_skipped() {
        let spec = make_recordable_spec(); // has empty delegated_capabilities
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            !json.contains("delegated_capabilities"),
            "Empty delegated_capabilities should be skipped. JSON: {}",
            json
        );
    }

    #[test]
    fn test_serde_non_empty_delegated_included() {
        let spec = make_recordable_spec_with_delegated();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(
            json.contains("delegated_capabilities"),
            "Non-empty delegated_capabilities should be present. JSON: {}",
            json
        );
    }

    // ══════════════════════════════════════════════
    //  Serde: SessionInfo
    // ══════════════════════════════════════════════

    #[test]
    fn test_serde_session_info() {
        let info = make_session_info();
        let json = serde_json::to_string(&info).unwrap();
        let rt: SessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.connector, info.connector);
        assert_eq!(rt.auth_key_id, info.auth_key_id);
    }

    // ══════════════════════════════════════════════
    //  Serde: full SessionScript
    // ══════════════════════════════════════════════

    #[test]
    fn test_serde_session_script_roundtrip() {
        let script = SessionScript {
            version: "1.0".to_string(),
            recorded_at: "20260227-10:00:00".to_string(),
            session: make_session_info(),
            operations: vec![
                RecordedOperation::GenerateObject {
                    spec: make_recordable_spec(),
                    context: "asym".to_string(),
                },
                RecordedOperation::DeleteObject {
                    object_id: 0x0042,
                    object_type: ObjectType::AsymmetricKey,
                    context: "asym".to_string(),
                },
                RecordedOperation::CreateAuthKey {
                    spec: make_recordable_spec_with_delegated(),
                    credential: "password".to_string(),
                },
            ],
        };
        let json = serde_json::to_string_pretty(&script).unwrap();
        let rt: SessionScript = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.version, "1.0");
        assert_eq!(rt.session.connector, "yhusb://serial=12345678");
        assert_eq!(rt.session.auth_key_id, 1);
        assert_eq!(rt.operations.len(), 3);
    }
}