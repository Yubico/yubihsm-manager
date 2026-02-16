use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};
use crate::hsm_operations::types::NewObjectSpec;
use serde::{Deserialize, Serialize};

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

    GenerateObject(RecordableObjectSpec),

    // ImportObject {
    //     spec: RecordableObjectSpec,
    //     /// Base64-encoded key data.  Sensitive data uses "<REDACTED>".
    //     #[serde(skip_serializing_if = "Vec::is_empty", default)]
    //     data_b64: Vec<String>,
    // },

    DeleteObject {
        object_id: u16,
        object_type: ObjectType,
    },
}