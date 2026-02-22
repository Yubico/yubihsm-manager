use std::fmt;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use crate::hsm_operations::types::NewObjectSpec;
use crate::hsm_operations::wrap::{WrapOpSpec, WrapKeyShares};

// #[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
// pub enum ScriptInputFormat {
//     #[default]
//     Raw,
//     FilePath,
// }
//
// impl Display for ScriptInputFormat {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             ScriptInputFormat::Raw => write!(f, "Raw data in HEX format"),
//             ScriptInputFormat::FilePath => write!(f, "Path to input file"),
//         }
//     }
// }

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
    pub password: String,  // "<PASSWORD>" placeholder during recording
}

/// Serde-friendly mirror of NewObjectSpec using real yubihsmrs types.
/// Serde auto-serializes ObjectType as "AsymmetricKey",
/// ObjectAlgorithm as "EcP256", ObjectCapability as "SignEcdsa", etc.
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
        NewObjectSpec::new(
            spec.id,
            spec.object_type,
            spec.label.clone(),
            spec.algorithm,
            spec.domains.clone(),
            spec.capabilities.clone(),
            spec.delegated_capabilities.clone(),
            vec![],
        )
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
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        data: Vec<String>,
        context: String,
    },

    ImportWrapKey {
        spec: RecordableObjectSpec,
        key: String,
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
    //
    //
    // // ── KSP guided setup (recorded as one composite operation) ──
    //
    // KspSetup {
    //     rsa_decrypt: bool,
    //     wrapkey_id: u16,
    //     domains: Vec<String>,
    //     shares: u8,
    //     threshold: u8,
    //     app_authkey_id: u16,
    //     app_authkey_password: String,     // "<PASSWORD>"
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     audit_authkey_id: Option<u16>,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     audit_authkey_password: Option<String>,  // "<PASSWORD>"
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     export_directory: Option<String>,
    //     delete_current_authkey: bool,
    // },
}