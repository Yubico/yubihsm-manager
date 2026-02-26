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

pub const REDACTED: &str = "<REDACTED>";

#[derive(Clone, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum RedactMode {
    #[default]
    Sensitive,
    All,
    None,
}

impl Display for RedactMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RedactMode::Sensitive => write!(f, "sensitive"),
            RedactMode::All => write!(f, "all"),
            RedactMode::None => write!(f, "none"),
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