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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "operation", content = "params")]
pub enum RecordedOperation {

    // Key management (generate / import / delete)

    GenerateObject(NewObjectSpec),

    ImportObject {
        spec: NewObjectSpec,
        /// Base64-encoded key data.  Sensitive data uses "<REDACTED>".
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        data_b64: Vec<String>,
    },

    DeleteObject {
        object_id: u16,
        object_type: String,
    },
}