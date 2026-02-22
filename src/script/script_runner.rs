use std::fmt::Display;
use std::{fmt, fs};
use std::path::Path;
use yubihsmrs::Session;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use crate::hsm_operations::asym::{AsymmetricOperations, JavaOps};
use crate::hsm_operations::auth::AuthenticationOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::ksp::KspOperations;
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::types::NewObjectSpec;
use crate::hsm_operations::wrap::{WrapOperations, WrapKeyType};
use crate::hsm_operations::validators::{aes_key_validator, pem_private_rsa_file_validator, pem_public_rsa_file_validator};
use crate::script::types::{RecordedOperation, RecordableObjectSpec, SessionScript};
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::helper_operations::display_wrapkey_shares;
use crate::ui::helper_io::{get_pem_from_file, write_bytes_to_file};
pub struct ScriptRunner;

impl ScriptRunner {
    /// Load a script from script file.
    pub fn load(path: &Path) -> Result<SessionScript, MgmError> {
        let content = fs::read_to_string(path)?;

        let script: SessionScript = serde_json::from_str(&content)
            .map_err(|e| MgmError::Error(format!("Failed to parse script: {}", e)))?;

        if script.version != "1.0" {
            return Err(MgmError::Error(format!(
                "Unsupported script version '{}'. Expected '1.0'", script.version)));
        }
        if script.operations.is_empty() {
            return Err(MgmError::Error("Script contains no operations".to_string()));
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
                let progress = ui.start_progress(Some(&step));
                match context.as_str() {
                    "asym" => {
                        if !is_asym_privkey_spec(spec) && !is_cert_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                new_spec.object_type, new_spec.id)));
                        }
                        AsymmetricOperations.generate(session, &new_spec)?;
                    },
                    "sunpkcs11" => {
                        if !is_asym_privkey_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                new_spec.object_type, new_spec.id)));
                        }
                        JavaOps.generate(session, &new_spec)?;
                    },
                    "sym"  => {
                            if !is_sym_spec(spec) {
                                return Err(MgmError::Error(format!(
                                    "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of a symmetric key.",
                                    new_spec.object_type, new_spec.id)));
                            }
                        SymmetricOperations.generate(session, &new_spec)?;
                    },
                    "wrap" => {
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

            RecordedOperation::ImportObject { spec, data, context } => {
                ui.display_info_message(&format!("{} Import {:?} 0x{:04x} ({:?})", step, spec.object_type, spec.id, spec.algorithm));

                match context.as_str() {
                    "asym" => {
                        if !is_asym_privkey_spec(spec) && !is_cert_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an asymmetric object.",
                                spec.object_type, spec.id)));
                        }
                    },
                    "sunpkcs11" => {
                        if !is_asym_privkey_spec(spec) && data.len() == 2 {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of an SunPKCS11 special case object.",
                                spec.object_type, spec.id)));
                        }
                    },
                    "sym" => {
                        if !is_sym_spec(spec) {
                            return Err(MgmError::Error(format!(
                                "Cannot execute generate of {:?} 0x{:04x}: Object type and/or algorithm are not of a symmetric object.",
                                spec.object_type, spec.id)));
                        }
                    }
                    other => return Err(MgmError::Error(format!("Import operation not supported in '{:?}' context: unknown properties of redacted data.", other))),
                }

                let mut new_spec: NewObjectSpec = spec.into();
                if data[0] == "<REDACTED>" {
                    match context.as_str() {
                        "asym" => {
                            if spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
                                let fp = ui.get_certificate_filepath("Enter path to PEM file containing X509Certificate:", true, None)?;
                                let pem = get_pem_from_file(&fp)?[0].to_owned();
                                let (_, _, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                new_spec.data.push(_bytes);
                            } else {
                                loop {
                                    let fp = ui.get_asymmetric_import_filepath("Enter path to PEM file containing asymmetric private key:",
                                                                               None)?;
                                    let pem = get_pem_from_file(&fp)?[0].to_owned();
                                    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                    if _algo == spec.algorithm && _type == spec.object_type {
                                        new_spec.data.push(_bytes);
                                        break;
                                    }
                                    ui.display_error_message(&format!("Wrong algorithm or type of asymmetric object. Expected private key and algorithm {:?}", new_spec.algorithm));
                                    if ui.get_confirmation("Skip this step? ")? {
                                        return Ok(());
                                    }
                                }
                            }
                        },
                        "sunpkcs11" => {
                            let fp = ui.get_sunpkcs11_import_filepath(
                                "Enter absolute path to PEM file containing private key and X509Certificate (Only the first object of its type will be imported):",
                                None)?;
                            let pems = get_pem_from_file(&fp)?;
                            for pem in pems.clone() {
                                let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                if _type == ObjectType::AsymmetricKey && _algo == spec.algorithm {
                                    new_spec.data.push(_bytes);
                                    break;
                                }
                            }
                            for pem in pems {
                                let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                if _algo == ObjectAlgorithm::OpaqueX509Certificate && _type == ObjectType::Opaque {
                                    new_spec.data.push(_bytes);
                                    break;
                                }
                            }
                        },
                        "sym" => {
                            loop {
                                let k = ui.get_aes_key_hex("Enter AES key in HEX format:")?;
                                let algo = SymmetricOperations::get_symkey_algorithm_from_keylen(k.len())?;
                                if algo == spec.algorithm {
                                    new_spec.data.push(k);
                                    break;
                                }
                                ui.display_error_message(&format!("Wrong algorithm or type of symmetric key. Expected algorithm is {:?}", new_spec.algorithm));
                                if ui.get_confirmation("Skip this step? ")? {
                                    return Ok(());
                                }
                            }
                        },
                        _ => unreachable!(),
                    }
                } else {
                     new_spec.data.extend(data.iter()
                                 .map(|d| hex::decode(d)
                                     .map_err(|e| MgmError::Error(format!("Invalid hex data: {}", e))))
                                 .collect::<Result<Vec<_>, _>>()?);
                }

                match context.as_str() {
                    "asym" =>  { AsymmetricOperations.import(session, &new_spec)?; },
                    "sunpkcs11" => { JavaOps.import(session, &new_spec)?; },
                    "sym" => { SymmetricOperations.import(session, &new_spec)?; },
                    _ => unreachable!()
                }
                Ok(())
            },

            RecordedOperation::ImportWrapKey { spec, key, n_threshold, n_shares } => {
                ui.display_info_message(&format!("{} Import WrapKey 0x{:04x}", step, spec.id));

                if !is_wrap_spec(spec) && !is_publicwrap_spec(spec) {
                    return Err(MgmError::Error(format!(
                        "Cannot execute import of {:?} 0x{:04x}: Object type and/or algorithm are not of a wrap object.",
                        spec.object_type, spec.id)));
                }

                let mut new_spec: NewObjectSpec = spec.into();
                if key == "<REDACTED>" {
                    match WrapOperations::get_wrapkey_type(new_spec.object_type, new_spec.algorithm)? {
                        WrapKeyType::Aes => {
                            loop {
                                let k = ui.get_aes_key_hex("Enter wrap key in HEX format :")?;
                                if WrapOperations::get_algorithm_from_keylen(k.len())? == new_spec.algorithm {
                                    new_spec.data.push(k);
                                    break;
                                }
                                ui.display_error_message(&format!("Wrong length of Wrap Key. Expected algorithm is {:?}", new_spec.algorithm));
                                if ui.get_confirmation("Skip this step? ")? {
                                    return Ok(());
                                }
                            }
                        },
                        WrapKeyType::Rsa => {
                            loop {
                                let filepath = ui.get_private_rsa_filepath("Enter path to PEM file containing private RSA key:")?;
                                let pem = get_pem_from_file(&filepath)?[0].to_owned();
                                let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                if _algo == new_spec.algorithm {
                                    new_spec.data.push(_bytes);
                                    break;
                                }
                                ui.display_error_message(&format!("Wrong algorithm of RSA Wrap Key. Expected algorithm is {:?}", new_spec.algorithm));
                                if ui.get_confirmation("Skip this step? ")? {
                                    return Ok(());
                                }
                            }
                        },
                        WrapKeyType::RsaPublic => {
                            loop {
                                let filepath = ui.get_public_rsa_filepath("Enter path to PEM file containing public RSA key:")?;
                                let pem = get_pem_from_file(&filepath)?[0].to_owned();
                                let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                                if _algo == new_spec.algorithm {
                                    new_spec.data.push(_bytes);
                                    break;
                                }
                                ui.display_error_message(&format!("Wrong algorithm of RSA Wrap Key. Expected algorithm is {:?}", new_spec.algorithm));
                                if ui.get_confirmation("Skip this step? ")? {
                                    return Ok(());
                                }
                            }
                        }
                    }
                } else {
                    new_spec.data = [hex::decode(key)?].to_vec();
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
                if context == "sunpkcs11" {
                    JavaOps.delete(session, *object_id, *object_type)?;
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
                let value =
                if credential == "<REDACTED>" {
                    if spec.algorithm == ObjectAlgorithm::Aes128YubicoAuthentication {
                        let pwd = ui.get_password("Enter user password:", true)?;
                        pwd.as_bytes().to_vec()
                    } else if spec.algorithm == ObjectAlgorithm::Ecp256YubicoAuthentication {
                        let pubkey = ui.get_public_ecp256_filepath("Enter path to ECP256 public key PEM file: ")?;
                        let pubkey = get_pem_from_file(&pubkey)?;
                        if pubkey.len() > 1 {
                            ui.display_warning("Warning!! More than one PEM object found in file. Only the first object is read");
                        }
                        let pubkey = pubkey[0].clone();

                        let (_type, _algo, _value) = AsymmetricOperations::parse_asym_pem(pubkey)?;
                        if _type != ObjectType::PublicKey && _algo != ObjectAlgorithm::EcP256 {
                            return Err(MgmError::InvalidInput(
                                "Invalid public key. Found object is either not a public key or not of curve secp256r1.".to_string()));
                        }
                        _value
                    } else {
                        return Err(MgmError::Error("Cannot execute Authentication Key creation: Unknown properties of redacted credential.".to_string()));
                    }
                } else {
                    hex::decode(credential).map_err(|e| MgmError::Error(format!("Invalid hex data: {}", e)))?
                };
                let mut new_spec: NewObjectSpec = spec.into();
                new_spec.data = vec![value];
                AuthenticationOperations.import(session, &new_spec)?;
                Ok(())
            },

        //
        //     RecordedOperation::KspSetup {
        //         rsa_decrypt, wrapkey_id, domains, shares, threshold,
        //         app_authkey_id, audit_authkey_id, export_directory,
        //         delete_current_authkey, ..
        //     } => {
        //         let (actual_id, _) = KspOperations::import_ksp_wrapkey(
        //             session, *wrapkey_id, domains, *rsa_decrypt, *shares, *threshold)?;
        //         ui.display_success_message(&format!("Imported KSP wrap key 0x{:04x}", actual_id));
        //         ui.display_warning("New wrap key shares differ from original. Keep the original shares.");
        //
        //         let app_pwd = ui.get_password(
        //             &format!("Enter password for app auth key 0x{:04x}:", app_authkey_id), true)?;
        //         KspOperations::import_app_authkey(
        //             session, *app_authkey_id, domains, *rsa_decrypt, app_pwd)?;
        //
        //         if let Some(audit_id) = audit_authkey_id {
        //             let audit_pwd = ui.get_password(
        //                 &format!("Enter password for audit auth key 0x{:04x}:", audit_id), true)?;
        //             KspOperations::import_audit_authkey(session, *audit_id, domains, audit_pwd)?;
        //         }
        //
        //         if export_directory.is_some() {
        //             ui.display_warning("Key export skipped during replay");
        //         }
        //         if *delete_current_authkey {
        //             ui.display_warning("Auth key deletion skipped during replay — would terminate session");
        //         }
        //         Ok(())
        //     },


            RecordedOperation::ExportWrapped { wrap_spec, objects, destination_directory} |
            RecordedOperation::BackupDevice { wrap_spec, objects, destination_directory} => {
                ui.display_info_message(&format!("{} Export wrapped objects using WrapKey 0x{:04x}", step, wrap_spec.wrapkey_id));

                let dir = if destination_directory == "<REDACTED>" {
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
                let wrapped = if wrapped_filepath == "<REDACTED>" {
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
                let dir = if source_directory == "<REDACTED>" {
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

/// Resolve input that could be a file path or inline hex/text data.
fn resolve_input_data(input: &str) -> Result<Vec<u8>, MgmError> {
    let path = Path::new(input);
    if path.exists() && path.is_file() {
        fs::read(path).map_err(|e| MgmError::Error(format!("Failed to read '{}': {}", input, e)))
    } else if let Ok(bytes) = hex::decode(input) {
        Ok(bytes)
    } else {
        Ok(input.as_bytes().to_vec())
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


// fn op_summary(op: &RecordedOperation) -> String {
//     match op {
//         RecordedOperation::GenerateObject(s) =>
//             format!("Generate {:?} 0x{:04x} ({:?})", s.object_type, s.id, s.algorithm),
//         RecordedOperation::ImportObject { spec, .. } =>
//             format!("Import {:?} 0x{:04x} ({:?})", spec.object_type, spec.id, spec.algorithm),
//         RecordedOperation::DeleteObject { object_id, object_type } =>
//             format!("Delete {:?} 0x{:04x}", object_type, object_id),
//         RecordedOperation::CreateAuthKey { spec, auth_type, .. } =>
//             format!("Create auth key 0x{:04x} ({})", spec.id, auth_type),
//         RecordedOperation::Sign { key_id, algorithm, .. } =>
//             format!("Sign with 0x{:04x} ({:?})", key_id, algorithm),
//         RecordedOperation::Decrypt { key_id, algorithm, .. } =>
//             format!("Decrypt with 0x{:04x} ({:?})", key_id, algorithm),
//         RecordedOperation::DeriveEcdh { key_id, .. } =>
//             format!("ECDH derive with 0x{:04x}", key_id),
//         RecordedOperation::SignAttestationCert { attested_key_id, .. } =>
//             format!("Sign attestation for 0x{:04x}", attested_key_id),
//         RecordedOperation::AesEncrypt { key_id, aes_mode, .. } =>
//             format!("AES encrypt ({}) with 0x{:04x}", aes_mode, key_id),
//         RecordedOperation::AesDecrypt { key_id, aes_mode, .. } =>
//             format!("AES decrypt ({}) with 0x{:04x}", aes_mode, key_id),
//         RecordedOperation::GetRandom { num_bytes } =>
//             format!("GetRandom({} bytes)", num_bytes),
//         RecordedOperation::ResetDevice => "Reset device".to_string(),
//         RecordedOperation::KspSetup { .. } => "KSP guided setup".to_string(),
//         RecordedOperation::BackupDevice { .. } => "Backup device".to_string(),
//         RecordedOperation::RestoreDevice { .. } => "Restore device".to_string(),
//         RecordedOperation::ExportWrapped { .. } => "Export wrapped".to_string(),
//         RecordedOperation::ImportWrapped { .. } => "Import wrapped".to_string(),
//     }
// }