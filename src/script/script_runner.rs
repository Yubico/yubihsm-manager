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
use crate::script::backend_json::JsonBackend;
use crate::traits::script_traits::ScriptBackend;
use yubihsmrs::Session;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use crate::hsm_operations::asym::{AsymmetricOperations, JavaOps};
use crate::hsm_operations::auth::AuthenticationOperations;
use crate::common::error::MgmError;
use crate::common::types::NewObjectSpec;
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::wrap::{WrapOperations, WrapKeyType};
use crate::script::script_types;
use crate::script::script_types::{RecordedOperation, RecordableObjectSpec, SessionScript};
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::helper_operations::{display_wrapkey_shares, get_aes_keylen_from_algorithm};
use crate::ui::helper_io::{get_pem_from_file, write_bytes_to_file};
pub struct ScriptRunner;

impl ScriptRunner {
    /// Load a script from script file.
    pub fn load(path: &Path) -> Result<SessionScript, MgmError> {

        let backend: Box<dyn ScriptBackend> = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Box::new(JsonBackend),
            _ => return Err(MgmError::Error("Unable to load script. Script file has no extension".to_string())),
        };

        let script = backend.read(path)?;

        if script.version != "1.0" {
            return Err(MgmError::Error(format!(
                "Unsupported script version '{}'. Expected '1.0'", script.version)));
        }

        Ok(script)
    }

    /// Execute all operations in sequence.
    pub fn run(
        ui: &impl YubihsmUi,
        session: &Session,
        script: &SessionScript,
        continue_on_error: bool,
    ) -> Result<(), MgmError> {
        let total = script.operations.len();
        let mut errors: Vec<(usize, String)> = Vec::new();
        ui.display_info_message(
            &format!("Replaying {} operations from script recorded at {}",
                     total, script.recorded_at));

        for (i, op) in script.operations.iter().enumerate() {
            let step = format!("[{}/{}]", i + 1, total);

            match Self::execute(ui, session, op, &step) {
                Ok(()) => {
                    ui.display_success_message(&format!("{} Done", step));
                },
                Err(e) => {
                    let msg = format!("{} Failed: {}", step, e);
                    if !continue_on_error {
                        ui.display_error_message(&msg);
                        return Err(e);
                    }
                    ui.display_warning(&msg);
                    errors.push((i + 1, e.to_string()));
                },
            }

        }

        if errors.is_empty() {
            ui.display_success_message("Script executed successfully");
        } else {
            ui.display_warning(&format!(
                "Script replay completed with {} error(s):", errors.len()));
            for (step, err) in &errors {
                ui.display_warning(&format!("  Step {}: {}", step, err));
            }
        }

        Ok(())
    }

    fn execute(
        ui: &impl YubihsmUi,
        session: &Session,
        op: &RecordedOperation,
        step: &str,
    ) -> Result<(), MgmError> {
        match op {
            RecordedOperation::GenerateObject {spec, context} => {
                ui.display_info_message(&format!("{} Generate {:?} 0x{:04x} ({:?})", step, spec.object_type, spec.id, spec.algorithm));
                let new_spec: NewObjectSpec = spec.into();
                let progress = ui.start_progress(Some(step));
                match context.as_str() {
                    AsymmetricOperations::ASYM_CONTEXT => {
                        if !is_asym_privkey_spec(spec) && !is_cert_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                new_spec.object_type, new_spec.id)));
                        }
                        AsymmetricOperations.generate(session, &new_spec)?;
                    },
                    JavaOps::SUNPKCS11_CONTEXT => {
                        if !is_asym_privkey_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                new_spec.object_type, new_spec.id)));
                        }
                        JavaOps.generate(session, &new_spec)?;
                    },
                    SymmetricOperations::SYM_CONTEXT  => {
                            if !is_sym_spec(spec) {
                                return Err(MgmError::Error(format!(
                                    "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of a symmetric key.",
                                    new_spec.object_type, new_spec.id)));
                            }
                        SymmetricOperations.generate(session, &new_spec)?;
                    },
                    WrapOperations::WRAP_CONTEXT => {
                        if !is_wrap_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of a wrap key.",
                                new_spec.object_type, new_spec.id)));
                        }
                        WrapOperations.generate(session, &new_spec)?;
                    },
                    other => return Err(MgmError::Error(format!("Generation operation not supported in '{:?}' context", other))),
                }
                ui.stop_progress(progress, None);
                Ok(())
            },

            RecordedOperation::ImportObject { spec, value: data, context } => {
                ui.display_info_message(&format!("{} Import {:?} 0x{:04x} ({:?})", step, spec.object_type, spec.id, spec.algorithm));
                let mut new_spec: NewObjectSpec = spec.into();
                match context.as_str() {
                    AsymmetricOperations::ASYM_CONTEXT => {
                        if !is_asym_privkey_spec(spec) && !is_cert_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute import of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                spec.object_type, spec.id)));
                        }
                        if data == script_types::PROMPT {
                            let prompt = if new_spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
                                "Enter path to PEM file containing an X509 certificate:".to_string()
                            } else {
                                format!("Enter path to PEM file containing an {} private key:", new_spec.algorithm)
                            };
                            let fp = ui.get_asymmetric_import_params_filepath(
                                prompt.as_str(), None, new_spec.object_type, new_spec.algorithm)?;
                            let pem = get_pem_from_file(&fp)?[0].to_owned();
                            let (_, _, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                            new_spec.data.push(_bytes);
                        } else {
                            let pem = get_pem_from_file(data)?[0].to_owned();
                            let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem.clone())?;
                            if _algo != new_spec.algorithm || _type != new_spec.object_type {
                                return Err(MgmError::Error(format!(
                                    "Cannot execute import of {:?} 0x{:04x}: Algorithm and/or object type of provided PEM data do not match expected algorithm and object type of the object.",
                                    spec.object_type, spec.id)));
                            }
                            new_spec.data.push(_bytes);
                        }
                        AsymmetricOperations.import(session, &new_spec)?;
                    },
                    JavaOps::SUNPKCS11_CONTEXT => {
                        if !is_asym_privkey_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an SunPKCS11 special case object.",
                                spec.object_type, spec.id)));
                        }

                        let pems = if data == script_types::PROMPT {
                            let fp = ui.get_sunpkcs11_import_filepath(
                                "Enter absolute path to PEM file containing private key and X509Certificate (Only the first object of its type will be imported):",
                                None)?;
                            get_pem_from_file(&fp)?
                        } else {
                            get_pem_from_file(data)?
                        };
                        for pem in pems.clone() {
                            let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem.clone())?;
                            if _type == ObjectType::AsymmetricKey && _algo == spec.algorithm {
                                new_spec.data.push(_bytes);
                                break;
                            }
                        }
                        for pem in pems {
                            let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem.clone())?;
                            if _algo == ObjectAlgorithm::OpaqueX509Certificate && _type == ObjectType::Opaque {
                                new_spec.data.push(_bytes);
                                break;
                            }
                        }
                        JavaOps.import(session, &new_spec)?;
                    },
                    SymmetricOperations::SYM_CONTEXT => {
                        if !is_sym_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute import of {:?} 0x{:04x}: Object type and/or algorithm are not of a symmetric object.",
                                spec.object_type, spec.id)));
                        }

                        if data == script_types::PROMPT {
                            let keylen = get_aes_keylen_from_algorithm(new_spec.algorithm)?;
                            let k = ui.get_aes_key_params_hex(format!("Enter AES key of length {} bytes in HEX format:", keylen).as_str(), keylen)?;
                            new_spec.data.push(k);
                        } else {
                            new_spec.data.push(hex::decode(data)?);
                        }
                        SymmetricOperations.import(session, &new_spec)?;
                    }
                    other => return Err(MgmError::Error(format!("Import operation not supported in '{:?}' context: unknown properties of masked data.", other))),
                }
                Ok(())
            },

            RecordedOperation::ImportWrapKey { spec, value: key, n_threshold, n_shares } => {
                ui.display_info_message(&format!("{} Import WrapKey 0x{:04x}", step, spec.id));

                if !is_wrap_spec(spec) && !is_publicwrap_spec(spec) {
                    return Err(MgmError::Error(format!(
                        "Cannot execute import of {:?} 0x{:04x}: Object type and/or algorithm are not of a wrap object.",
                        spec.object_type, spec.id)));
                }

                let mut new_spec: NewObjectSpec = spec.into();
                let wrapkey_type = WrapOperations::get_wrapkey_type(&new_spec.object_type, &new_spec.algorithm)?;
                match wrapkey_type {
                    WrapKeyType::Aes => {
                        if key == script_types::PROMPT {
                            let kl = get_aes_keylen_from_algorithm(new_spec.algorithm)?;
                            let k = ui.get_aes_key_params_hex(format!("Enter Wrap Key of length {} bytes in HEX format:", kl).as_str(), kl)?;
                            new_spec.data.push(k);
                        } else {
                            new_spec.data.push(hex::decode(key)?);
                        }
                    },
                    WrapKeyType::Rsa | WrapKeyType::RsaPublic => {
                        if key == script_types::PROMPT {
                            let filepath = if wrapkey_type == WrapKeyType::Rsa {
                                ui.get_asymmetric_import_params_filepath(
                                    format!("Enter path to PEM file containing an {} private key:", new_spec.algorithm).as_str(), None, ObjectType::AsymmetricKey, new_spec.algorithm)?
                            } else {
                                ui.get_asymmetric_import_params_filepath(
                                    format!("Enter path to PEM file containing an {} public key:", new_spec.algorithm).as_str(), None, ObjectType::PublicKey, new_spec.algorithm)?
                            };
                            let pem = get_pem_from_file(&filepath)?[0].to_owned();
                            let (_, _, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                            new_spec.data.push(_bytes);
                        } else {
                            let filepath = key.to_string();
                            let pem = get_pem_from_file(&filepath)?[0].to_owned();
                            let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                            if _algo != new_spec.algorithm || (_type != ObjectType::AsymmetricKey && wrapkey_type == WrapKeyType::Rsa) || (_type != ObjectType::PublicKey && wrapkey_type == WrapKeyType::RsaPublic) {
                                return Err(MgmError::Error(format!(
                                    "Cannot execute import of {:?} 0x{:04x}: Algorithm of provided PEM data does not match expected algorithm of the object.",
                                    spec.object_type, spec.id)));
                            }
                            new_spec.data.push(_bytes);
                        }
                    }
                }
                WrapOperations.import(session, &new_spec)?;
                if *n_threshold != 0 && *n_shares != 0 {
                    let split_key = WrapOperations::split_wrap_key(&new_spec, *n_threshold, *n_shares)?;
                    display_wrapkey_shares(ui, split_key.shares_data)?;
                }
                Ok(())
            },

            RecordedOperation::DeleteObject { object_id, object_type, context} => {
                ui.display_info_message(&format!("{} Delete {:?} 0x{:04x}", step, object_type, object_id));
                if context == JavaOps::SUNPKCS11_CONTEXT {
                    JavaOps.delete(session, *object_id, object_type)?;
                } else {
                    session.delete_object(*object_id, *object_type)?;
                }
                Ok(())
            },

            RecordedOperation::CreateAuthKey { spec, credential } => {
                ui.display_info_message(&format!("{} Create auth key 0x{:04x} ({})",
                                                 step,
                                                 spec.id,
                                                 if spec.algorithm == ObjectAlgorithm::Aes128YubicoAuthentication { "Derived password" } else { "ECP256 public key" }));
                let mut new_spec: NewObjectSpec = spec.into();
                if new_spec.algorithm == ObjectAlgorithm::Aes128YubicoAuthentication {
                    if credential == script_types::PROMPT {
                        let pwd = ui.get_password("Enter user password:", true)?;
                        new_spec.data.push(pwd.as_bytes().to_vec());
                    } else {
                       new_spec.data.push(hex::decode(credential)?);
                    }
                } else if new_spec.algorithm == ObjectAlgorithm::Ecp256YubicoAuthentication {
                    if credential == script_types::PROMPT {
                        let filepath = ui.get_asymmetric_import_params_filepath(
                            "Enter path to PEM file containing an ECP256 public key:", None, ObjectType::PublicKey, ObjectAlgorithm::EcP256)?;
                        let pubkey = get_pem_from_file(&filepath)?[0].to_owned();
                        let (_, _, _bytes) = AsymmetricOperations::parse_asym_pem(pubkey)?;
                        new_spec.data.push(_bytes);
                    } else {
                        let filepath = credential.to_string();
                        let pubkey = get_pem_from_file(&filepath)?[0].clone();
                        let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pubkey)?;
                        if _algo != ObjectAlgorithm::EcP256 || _type != ObjectType::PublicKey {
                            return Err(MgmError::Error("Cannot execute Authentication Key creation: Algorithm or type of provided PEM data do not match expected algorithm and type of the object.".to_string()));
                        }
                        new_spec.data.push(_bytes);
                    }
                } else {
                    return Err(MgmError::Error("Cannot execute Authentication Key creation: Unsupported algorithm of authentication key.".to_string()));
                }

                AuthenticationOperations.import(session, &new_spec)?;
                Ok(())
            },

            RecordedOperation::ExportWrapped { wrap_spec, objects, destination_directory} |
            RecordedOperation::BackupDevice { wrap_spec, objects, destination_directory} => {
                ui.display_info_message(&format!("{} Export wrapped objects using WrapKey 0x{:04x}", step, wrap_spec.wrapkey_id));

                let dir = if destination_directory == script_types::PROMPT {
                    ui.get_path_input(
                        "Enter path to backup directory:",
                        false,
                        Some("."),
                        Some("Default is current directory"))?
                } else {
                    destination_directory.clone()
                };

                let wrapped_objects = WrapOperations::export_wrapped(session, wrap_spec, objects)?;
                for object in wrapped_objects {
                    if object.error.is_some() {
                        ui.display_warning(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()).as_str());
                        continue;
                    }
                    let filename = format!("{}/0x{:04x}-{}.yhw", dir, object.object_id, object.object_type);
                    write_bytes_to_file(ui,&object.wrapped_data, filename.as_str())?;
                }
                Ok(())
            },

            RecordedOperation::ImportWrapped { wrap_spec, wrapped_filepath, new_key_spec } => {
                ui.display_info_message(&format!("{} Import wrapped object using WrapKey 0x{:04x}", step, wrap_spec.wrapkey_id));
                let wrapped = if wrapped_filepath == script_types::PROMPT {
                    ui.get_path_input(
                        "Enter absolute path to wrapped object file:",
                        true,
                        None,
                        Some("Files containing wrapped YubiHSM objects usually have the file extension .yhw"))?
                } else {
                    wrapped_filepath.clone()
                };
                let wrapped = fs::read(&wrapped)?;
                let new_spec: Option<NewObjectSpec> = if new_key_spec.is_some() {
                    Some(new_key_spec.as_ref().unwrap().into())
                } else {
                    None
                };
                WrapOperations::import_wrapped(session, wrap_spec, &wrapped, new_spec)?;
                Ok(())
            },

            RecordedOperation::RestoreDevice { wrap_spec, source_directory } => {
                ui.display_info_message(&format!("{} Restore device using WrapKey 0x{:04x}", step, wrap_spec.wrapkey_id));
                let dir = if source_directory == script_types::PROMPT {
                    ui.get_path_input(
                        "Enter path to backup directory:",
                        false,
                        Some("."),
                        Some("Default is current directory"))?
                } else {
                    source_directory.clone()
                };

                let files: Vec<_> = match scan_dir::ScanDir::files().read(dir.clone(), |iter| {
                    iter.filter(|(_, name)| name.ends_with(".yhw")).map(|(entry, _)| entry.path()).collect()
                }) {
                    Ok(f) => f,
                    Err(err) => {
                        ui.display_error_message(err.to_string().as_str());
                        return Err(MgmError::Error("Failed to read files".to_string()))
                    }
                };

                if files.is_empty() {
                    ui.display_info_message(format!("No backup files were found in {}", dir).as_str());
                    return Ok(())
                }

                for f in files {
                    let wrapped = fs::read(&f)?;

                    let res = WrapOperations::import_wrapped(session, wrap_spec, &wrapped, None);
                    match res {
                        Ok(handle) => {
                            ui.display_success_message(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id).as_str());
                        },
                        Err(e) => {
                            ui.display_error_message(format!("Failed to import wrapped object from file {}: {}. Skipping...", f.display(), e).as_str());
                        }
                    }
                }

                Ok(())
            },
        }
    }
}

fn is_asym_privkey_spec(spec: &RecordableObjectSpec) -> bool {
    matches!(spec.object_type, ObjectType::AsymmetricKey)
        && (AsymmetricOperations::is_rsa_key_algorithm(&spec.algorithm)
            || AsymmetricOperations::is_ec_key_algorithm(&spec.algorithm)
            || spec.algorithm == ObjectAlgorithm::Ed25519)
}

fn is_cert_spec(spec: &RecordableObjectSpec) -> bool {
    spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate
        && spec.object_type == ObjectType::Opaque
}

fn is_sym_spec(spec: &RecordableObjectSpec) -> bool {
    spec.object_type == ObjectType::SymmetricKey && SymmetricOperations::is_aes_algorithm(&spec.algorithm)
}

fn is_wrap_spec(spec: &RecordableObjectSpec) -> bool {
    spec.object_type == ObjectType::WrapKey && WrapOperations.get_generation_algorithms().contains(&spec.algorithm.into())
}

fn is_publicwrap_spec(spec: &RecordableObjectSpec) -> bool {
    spec.object_type == ObjectType::PublicWrapKey && AsymmetricOperations::is_rsa_key_algorithm(&spec.algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::script::backend_json::JsonBackend;
    use crate::script::script_types::{RecordableObjectSpec, RecordedOperation, SessionInfo, SessionScript};
    use crate::script::script_recorder::SessionRecorder;
    use crate::script::script_types::MaskLevel;
    use crate::hsm_operations::wrap::{WrapKeyType, WrapOpSpec, WrapType};
    use yubihsmrs::object::{
        ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType,
    };

    // ── Helper builders ──

    fn make_asym_rsa_spec() -> RecordableObjectSpec {
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

    fn make_asym_ec_spec() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0002,
            object_type: ObjectType::AsymmetricKey,
            label: "ec-key".to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignEcdsa],
            delegated_capabilities: vec![],
        }
    }

    fn make_sym_spec() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0020,
            object_type: ObjectType::SymmetricKey,
            label: "aes-key".to_string(),
            algorithm: ObjectAlgorithm::Aes256,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::EncryptCbc],
            delegated_capabilities: vec![],
        }
    }

    fn make_wrap_aes_spec() -> RecordableObjectSpec {
        RecordableObjectSpec {
            id: 0x0030,
            object_type: ObjectType::WrapKey,
            label: "wrap-key".to_string(),
            algorithm: ObjectAlgorithm::Aes256CcmWrap,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::ExportWrapped],
            delegated_capabilities: vec![],
        }
    }

    fn make_session_info() -> SessionInfo {
        SessionInfo {
            connector: "yhusb://serial=12345678".to_string(),
            auth_key_id: 1,
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

    /// Write a SessionScript to a temporary JSON file and return the path.
    fn write_test_script(dir: &TempDir, filename: &str, script: &SessionScript) -> std::path::PathBuf {
        let path = dir.path().join(filename);
        let json = serde_json::to_string_pretty(script).unwrap();
        fs::write(&path, json).unwrap();
        path
    }

    fn make_valid_script(ops: Vec<RecordedOperation>) -> SessionScript {
        SessionScript {
            version: "1.0".to_string(),
            recorded_at: "20260227-10:00:00".to_string(),
            session: make_session_info(),
            operations: ops,
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  is_asym_privkey_spec
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_is_asym_privkey_rsa() {
        let mut spec = make_asym_ec_spec();
        assert!(is_asym_privkey_spec(&spec));

        spec.algorithm = ObjectAlgorithm::EcP256;
        assert!(is_asym_privkey_spec(&spec));

        spec.algorithm = ObjectAlgorithm::Ed25519;
        assert!(is_asym_privkey_spec(&spec));

        spec.algorithm = ObjectAlgorithm::OpaqueX509Certificate;
        assert!(!is_asym_privkey_spec(&spec));

        spec.algorithm = ObjectAlgorithm::EcP256;
        spec.object_type = ObjectType::PublicKey;
        assert!(!is_asym_privkey_spec(&spec));

        spec.object_type = ObjectType::Opaque;
        assert!(!is_asym_privkey_spec(&spec));
    }

    // ══════════════════════════════════════════════════════════════
    //  is_cert_spec
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_is_cert_spec() {
        let mut spec = RecordableObjectSpec {
            id: 0x0010,
            object_type: ObjectType::Opaque,
            label: "cert".to_string(),
            algorithm: ObjectAlgorithm::OpaqueX509Certificate,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::ExportableUnderWrap],
            delegated_capabilities: vec![],
        };

        assert!(is_cert_spec(&spec));

        spec.algorithm = ObjectAlgorithm::EcP256;
        assert!(!is_cert_spec(&spec));

        spec.object_type = ObjectType::Opaque;
        spec.algorithm = ObjectAlgorithm::Rsa2048;
        assert!(!is_cert_spec(&spec));
    }

    // ══════════════════════════════════════════════════════════════
    //  is_sym_spec
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_is_sym_spec() {
        let mut spec = make_sym_spec();

        assert!(is_sym_spec(&spec));

        spec.algorithm = ObjectAlgorithm::EcP256;
        assert!(!is_sym_spec(&spec));

        spec.object_type = ObjectType::Opaque;
        spec.algorithm = ObjectAlgorithm::Aes128;
        assert!(!is_sym_spec(&spec));
    }

    // ══════════════════════════════════════════════════════════════
    //  is_wrap_spec
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_is_wrap_spec() {
        let mut spec = RecordableObjectSpec {
            id: 0x0031,
            object_type: ObjectType::WrapKey,
            label: "rsa-wrap".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::ImportWrapped],
            delegated_capabilities: vec![],
        };

        assert!(is_wrap_spec(&spec));

        spec.algorithm = ObjectAlgorithm::Aes192CcmWrap;
        assert!(is_wrap_spec(&spec));

        spec.algorithm = ObjectAlgorithm::Aes192;
        assert!(!is_wrap_spec(&spec));

        spec.algorithm = ObjectAlgorithm::EcP256;
        assert!(!is_wrap_spec(&spec));

        spec.object_type = ObjectType::Opaque;
        spec.algorithm = ObjectAlgorithm::Aes128CcmWrap;
        assert!(!is_wrap_spec(&spec));
    }

    // ══════════════════════════════════════════════════════════════
    //  is_publicwrap_spec
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_is_publicwrap_spec() {
        let mut spec = RecordableObjectSpec {
            id: 0x0032,
            object_type: ObjectType::PublicWrapKey,
            label: "pub-wrap".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::ExportWrapped],
            delegated_capabilities: vec![],
        };

        assert!(is_publicwrap_spec(&spec));

        spec.algorithm = ObjectAlgorithm::Aes192CcmWrap;
        assert!(!is_publicwrap_spec(&spec));

        spec.object_type = ObjectType::PublicKey;
        spec.algorithm = ObjectAlgorithm::Rsa2048;
        assert!(!is_publicwrap_spec(&spec));
    }
    // ══════════════════════════════════════════════════════════════
    //  ScriptRunner::load — happy paths
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_load_valid_script() {
        let dir = TempDir::new().unwrap();
        let script = make_valid_script(vec![]);
        let path = write_test_script(&dir, "valid.json", &script);
        let loaded = ScriptRunner::load(&path).unwrap();
        assert_eq!(loaded.version, "1.0");
        assert_eq!(loaded.session.connector, "yhusb://serial=12345678");
        assert!(loaded.operations.is_empty());
    }

    #[test]
    fn test_load_script_with_operations() {
        let dir = TempDir::new().unwrap();
        let ops = vec![
            RecordedOperation::GenerateObject {
                spec: make_asym_rsa_spec(),
                context: "asym".to_string(),
            },
            RecordedOperation::DeleteObject {
                object_id: 0x0001,
                object_type: ObjectType::AsymmetricKey,
                context: "asym".to_string(),
            },
        ];
        let script = make_valid_script(ops);
        let path = write_test_script(&dir, "with_ops.json", &script);
        let loaded = ScriptRunner::load(&path).unwrap();
        assert_eq!(loaded.operations.len(), 2);
    }

    // ══════════════════════════════════════════════════════════════
    //  ScriptRunner::load — error paths
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_load_rejects_wrong_version() {
        let dir = TempDir::new().unwrap();
        let script = SessionScript {
            version: "2.0".to_string(),
            recorded_at: "20260227-10:00:00".to_string(),
            session: make_session_info(),
            operations: vec![],
        };
        let path = write_test_script(&dir, "wrong_version.json", &script);
        let err = ScriptRunner::load(&path).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Unsupported script version"), "Got: {}", msg);
    }

    #[test]
    fn test_load_rejects_no_extension() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("noext");
        fs::write(&path, "{}").unwrap();
        let err = ScriptRunner::load(&path).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("no extension"), "Got: {}", msg);
    }

    #[test]
    fn test_load_rejects_wrong_extension() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("script.yaml");
        std::fs::write(&path, "version: 1.0").unwrap();
        let err = ScriptRunner::load(&path).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("no extension") || msg.contains("Unable to load"), "Got: {}", msg);
    }

    #[test]
    fn test_load_rejects_nonexistent_file() {
        let path = Path::new("/nonexistent/script.json");
        assert!(ScriptRunner::load(path).is_err());
    }

    #[test]
    fn test_load_rejects_invalid_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, "not json at all").unwrap();
        assert!(ScriptRunner::load(&path).is_err());
    }

    // ══════════════════════════════════════════════════════════════
    //  End-to-end pipeline: Recorder → JSON file → ScriptRunner::load
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_e2e_record_then_load_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("e2e_empty.json");

        // Record a single operation so the file is created
        let rec = SessionRecorder::new(
            "yhusb://serial=E2E00000".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            MaskLevel::Sensitive,
            Box::new(JsonBackend),
        );
        let op = RecordedOperation::GenerateObject {
            spec: make_asym_rsa_spec(),
            context: "asym".to_string(),
        };
        rec.record(op).unwrap();

        // Load the script back via ScriptRunner
        let script = ScriptRunner::load(&path).unwrap();
        assert_eq!(script.version, "1.0");
        assert_eq!(script.session.connector, "yhusb://serial=E2E00000");
        assert_eq!(script.session.auth_key_id, 1);
        assert_eq!(script.operations.len(), 1);
    }

    #[test]
    fn test_e2e_record_diverse_then_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("e2e_diverse.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=DIVERSE1".to_string(),
            42,
            path.to_str().unwrap().to_string(),
            MaskLevel::None,
            Box::new(JsonBackend),
        );

        // Record a mix of different operation types
        rec.record(RecordedOperation::GenerateObject {
            spec: make_asym_rsa_spec(),
            context: "asym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::GenerateObject {
            spec: make_sym_spec(),
            context: "sym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ImportObject {
            spec: make_asym_ec_spec(),
            value: "/path/to/key.pem".to_string(),
            context: "asym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::CreateAuthKey {
            spec: RecordableObjectSpec {
                id: 0x0100,
                object_type: ObjectType::AuthenticationKey,
                label: "admin".to_string(),
                algorithm: ObjectAlgorithm::Aes128YubicoAuthentication,
                domains: vec![ObjectDomain::One],
                capabilities: vec![ObjectCapability::PutAuthenticationKey],
                delegated_capabilities: vec![ObjectCapability::SignPkcs],
            },
            credential: "secret".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ExportWrapped {
            wrap_spec: make_wrap_op_spec(),
            objects: vec![
                ObjectHandle { object_id: 1, object_type: ObjectType::AsymmetricKey },
            ],
            destination_directory: "/tmp/backup".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::DeleteObject {
            object_id: 0x0001,
            object_type: ObjectType::AsymmetricKey,
            context: "asym".to_string(),
        }).unwrap();

        assert_eq!(rec.operation_count(), 6);

        // Load and verify
        let script = ScriptRunner::load(&path).unwrap();
        assert_eq!(script.session.auth_key_id, 42);
        assert_eq!(script.operations.len(), 6);
    }

    #[test]
    fn test_e2e_drop_flush_then_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("e2e_drop.json");
        {
            let rec = SessionRecorder::new(
                "yhusb://serial=DROP0001".to_string(),
                7,
                path.to_str().unwrap().to_string(),
                MaskLevel::All,
                Box::new(JsonBackend),
            );
            rec.record(RecordedOperation::GenerateObject {
                spec: make_wrap_aes_spec(),
                context: "wrap".to_string(),
            }).unwrap();
            // Drop triggers flush
        }

        let script = ScriptRunner::load(&path).unwrap();
        assert_eq!(script.session.auth_key_id, 7);
        assert_eq!(script.operations.len(), 1);
    }

    #[test]
    fn test_e2e_incremental_recording_always_consistent() {
        // Each record() flushes the full list — after N records the file has exactly N ops
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("e2e_incremental.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=INCR0001".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            MaskLevel::Sensitive,
            Box::new(JsonBackend),
        );

        for i in 0..5u16 {
            rec.record(RecordedOperation::DeleteObject {
                object_id: i,
                object_type: ObjectType::AsymmetricKey,
                context: "asym".to_string(),
            }).unwrap();

            // At every step the file should be loadable and have i+1 operations
            let script = ScriptRunner::load(&path).unwrap();
            assert_eq!(script.operations.len(), (i + 1) as usize);
        }
    }
}