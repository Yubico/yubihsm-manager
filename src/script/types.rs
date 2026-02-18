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

    GenerateObject {
        spec: RecordableObjectSpec,
        context: String,
    },

    ImportObject {
        spec: RecordableObjectSpec,
        #[serde(skip_serializing_if = "Vec::is_empty", default)]
        data: Vec<String>,
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

    // // ── Asymmetric operations ──
    //
    // Sign {
    //     key_id: u16,
    //     algorithm: String,
    //     /// Path to input file or hex-encoded inline data
    //     input: String,
    //     /// Path where signature was written (if any)
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     output_file: Option<String>,
    // },
    //
    // Decrypt {
    //     key_id: u16,
    //     algorithm: String,
    //     /// Path to input file or hex-encoded inline data
    //     input: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     output_file: Option<String>,
    // },
    //
    // DeriveEcdh {
    //     key_id: u16,
    //     peer_pubkey_file: String,
    // },
    //
    // SignAttestationCert {
    //     attested_key_id: u16,
    //     attesting_key_id: u16,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     template_cert_file: Option<String>,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     output_file: Option<String>,
    // },
    //
    // // ── Symmetric operations ──
    //
    // AesEncrypt {
    //     key_id: u16,
    //     aes_mode: String,     // "Ecb" or "Cbc"
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     iv_hex: Option<String>,
    //     /// Path to input file or hex-encoded inline data
    //     input: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     output_file: Option<String>,
    // },
    //
    // AesDecrypt {
    //     key_id: u16,
    //     aes_mode: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     iv_hex: Option<String>,
    //     input: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     output_file: Option<String>,
    // },
    //
    // // ── Wrap operations ──
    //
    // ExportWrapped {
    //     wrapkey_id: u16,
    //     wrapkey_type: String,
    //     wrap_type: String,
    //     object_ids: Vec<u16>,
    //     output_directory: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     oaep_algorithm: Option<String>,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     mgf1_algorithm: Option<String>,
    // },
    //
    // ImportWrapped {
    //     wrapkey_id: u16,
    //     wrapkey_type: String,
    //     wrap_type: String,
    //     input_file: String,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     oaep_algorithm: Option<String>,
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     mgf1_algorithm: Option<String>,
    //     /// Only for RSA key-only wrap imports
    //     #[serde(skip_serializing_if = "Option::is_none")]
    //     new_key_spec: Option<SerializableObjectSpec>,
    // },
    //
    // // ── Device operations ──
    //
    // GetRandom {
    //     num_bytes: usize,
    // },
    //
    // BackupDevice {
    //     wrapkey_id: u16,
    //     output_directory: String,
    // },
    //
    // RestoreDevice {
    //     wrapkey_id: u16,
    //     input_directory: String,
    // },
    //
    // ResetDevice,
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