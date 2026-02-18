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
use crate::hsm_operations::wrap::WrapOperations;
use crate::script::types::{RecordedOperation, RecordableObjectSpec, SessionScript};
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
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
            // ui.display_info_message(&format!("{} {}", step, op_summary(op)));
            ui.display_info_message(&step);

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
                ui.display_info_message(&format!("Generate {:?} 0x{:04x} ({:?})", spec.object_type, spec.id, spec.algorithm));
                let new_spec: NewObjectSpec = spec.into();
                let progress = ui.start_progress(Some(&step));
                match context.as_str() {
                    "asym" => { AsymmetricOperations.generate(session, &new_spec)?; },
                    "sunpkcs11" => { JavaOps.generate(session, &new_spec)?; },
                    "sym"  => { SymmetricOperations.generate(session, &new_spec)?; },
                    "wrap" => { WrapOperations.generate(session, &new_spec)?; },
                    other => return Err(MgmError::Error(format!("Cannot generate in {:?} context", other))),
                }
                ui.stop_progress(progress, None);
                Ok(())
            },

            RecordedOperation::ImportObject { spec, data } => {
                ui.display_info_message(&format!("Import {:?} 0x{:04x} ({:?})", spec.object_type, spec.id, spec.algorithm));
                let mut value = Vec::new();
                if data[0] == "<REDACTED>" {
                    if AsymmetricOperations::is_rsa_key_algorithm(&spec.algorithm) ||
                        AsymmetricOperations::is_ec_key_algorithm(&spec.algorithm) ||
                        spec.algorithm == ObjectAlgorithm::Ed25519 ||
                        spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
                        let filepath = if spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
                            ui.get_asymmetric_import_filepath("Enter path to PEM file containing X509Certificate:",
                                None)?
                        } else {
                            ui.get_asymmetric_import_filepath("Enter path to PEM file containing asymmetric key:",
                                                              None)?
                        };
                        let pem = get_pem_from_file(&filepath)?;
                        let pem = pem[0].to_owned();
                        let (_, _, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                        // TODO Validate algo and type of the read pem key against spec
                        value.push(_bytes);
                    } else if spec.object_type == ObjectType::SymmetricKey || spec.object_type == ObjectType::WrapKey {
                        let key = ui.get_aes_key_hex("Enter AES key in HEX format:")?;
                        // let _algo = SymmetricOperations::get_symkey_algorithm_from_keylen(key.len())?;
                        // TODO Validate algo against spec
                        value.push(key);
                    } else if spec.algorithm == ObjectAlgorithm::Aes128YubicoAuthentication {
                        let pwd = ui.get_password("Enter user password:", true)?;
                        value.push(pwd.as_bytes().to_vec());

                    } else {
                        return Err(MgmError::Error(format!(
                            "Cannot execute import of {:?} 0x{:04x}: unknown properties of redacted data. Import manually.",
                            spec.object_type, spec.id)));
                    }

                    if data.len() > 1 && spec.object_type == ObjectType::AsymmetricKey {
                        // Must be a java key, which means we need to read a certificate too
                        let filepath = ui.get_asymmetric_import_filepath("Enter path to PEM file containing X509Certificate:",
                                                              None)?;
                        let pem = get_pem_from_file(&filepath)?;
                        let pem = pem[0].to_owned();
                        let (_, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
                        if _algo != ObjectAlgorithm::OpaqueX509Certificate {
                            return Err(MgmError::Error(format!("File does not contain X509Certificate.")));
                        }
                        value.push(_bytes);
                    }
                } else {
                     value = data.iter()
                                 .map(|d| hex::decode(d)
                                     .map_err(|e| MgmError::Error(format!("Invalid hex data: {}", e))))
                                 .collect::<Result<Vec<_>, _>>()?;
                }

                let mut new_spec: NewObjectSpec = spec.into();
                new_spec.data = value;
                match spec.object_type {
                    ObjectType::AsymmetricKey     => {
                        if new_spec.data.len() > 1 {
                            JavaOps.import(session, &new_spec)?;
                        } else {
                            AsymmetricOperations.import(session, &new_spec)?;
                        }
                    },
                    ObjectType::SymmetricKey      => { SymmetricOperations.import(session, &new_spec)?; },
                    ObjectType::WrapKey
                    | ObjectType::PublicWrapKey    => { WrapOperations.import(session, &new_spec)?; },
                    ObjectType::AuthenticationKey => { AuthenticationOperations.import(session, &new_spec)?; },
                    other => return Err(MgmError::Error(format!("Unknown object type {:?}", other))),
                }
                Ok(())
            },

            RecordedOperation::DeleteObject { object_id, object_type, context} => {
                ui.display_info_message(&format!("Delete {:?} 0x{:04x}", object_type, object_id));
                if context == "sunpkcs11" {
                    JavaOps.delete(session, *object_id, *object_type)?;
                } else {
                    session.delete_object(*object_id, *object_type)?;
                }
                Ok(())
            },

            RecordedOperation::CreateAuthKey { spec, credential } => {
                ui.display_info_message(&format!("Create auth key 0x{:04x} ({})",
                                                 spec.id,
                                                 if spec.algorithm == ObjectAlgorithm::Aes128YubicoAuthentication {"Derived password"} else {"ECP256 public key"}));
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
        //     RecordedOperation::Sign { key_id, algorithm, input, output_file } => {
        //         let data = resolve_input_data(input)?;
        //         let sig = AsymmetricOperations::sign(session, *key_id, algorithm, &data)?;
        //         if let Some(path) = output_file {
        //             fs::write(path, &sig)
        //                 .map_err(|e| MgmError::Error(format!("Write failed: {}", e)))?;
        //         }
        //         Ok(())
        //     },
        //
        //     RecordedOperation::Decrypt { key_id, algorithm, input, output_file } => {
        //         let data = resolve_input_data(input)?;
        //         let plain = AsymmetricOperations::decrypt(session, *key_id, algorithm, &data)?;
        //         if let Some(path) = output_file {
        //             fs::write(path, &plain)
        //                 .map_err(|e| MgmError::Error(format!("Write failed: {}", e)))?;
        //         }
        //         Ok(())
        //     },
        //
        //     RecordedOperation::AesEncrypt { key_id, aes_mode, iv_hex, input, output_file } |
        //     RecordedOperation::AesDecrypt { key_id, aes_mode, iv_hex, input, output_file } => {
        //         let encrypt = matches!(op, RecordedOperation::AesEncrypt { .. });
        //         let data = resolve_input_data(input)?;
        //         let iv = iv_hex.as_ref()
        //                        .map(|h| hex::decode(h).map_err(|e| MgmError::InvalidInput(format!("Invalid IV: {}", e))))
        //                        .transpose()?
        //             .unwrap_or_default();
        //         let result = match (encrypt, aes_mode.as_str()) {
        //             (true,  "Ecb") => session.encrypt_aes_ecb(*key_id, &data)?,
        //             (true,  "Cbc") => session.encrypt_aes_cbc(*key_id, &iv, &data)?,
        //             (false, "Ecb") => session.decrypt_aes_ecb(*key_id, &data)?,
        //             (false, "Cbc") => session.decrypt_aes_cbc(*key_id, &iv, &data)?,
        //             (_, mode) => return Err(MgmError::InvalidInput(format!("Unknown AES mode: '{}'", mode))),
        //         };
        //         if let Some(path) = output_file {
        //             fs::write(path, &result).map_err(|e| MgmError::Error(format!("Write failed: {}", e)))?;
        //         }
        //         Ok(())
        //     },
        //
        //     RecordedOperation::DeriveEcdh { key_id, peer_pubkey_file } => {
        //         let pems = crate::ui::helper_io::get_pem_from_file(peer_pubkey_file)?;
        //         let hsm_key = session.get_object_info(*key_id, ObjectType::AsymmetricKey)?;
        //         let _ = AsymmetricOperations::derive_ecdh(session, &hsm_key, pems[0].clone())?;
        //         Ok(())
        //     },
        //
            RecordedOperation::SignAttestationCert {
                attested_key_id, attesting_key_id, template_cert
            } => {
                ui.display_info_message(format!("Sign attestation for 0x{:04x}", attested_key_id).as_str());
                let template = if let Some(cert) = template_cert {
                    Some(pem::parse(cert)?)
                } else {
                    None
                };
                let cert = AsymmetricOperations::get_attestation_cert(
                    session, *attested_key_id, *attesting_key_id, template)?;
                let filename = format!("0x{:04x}by0x{:04x}_attestation_cert.pem", attested_key_id, attesting_key_id);
                write_bytes_to_file(ui, &cert.to_string().into_bytes(), &filename)?;
                Ok(())
            },
        //
        //     RecordedOperation::GetRandom { num_bytes } => {
        //         let _ = session.get_random(*num_bytes)?;
        //         Ok(())
        //     },
        //
        //     RecordedOperation::ResetDevice => {
        //         session.reset()?;
        //         Ok(())
        //     },
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
        //
        //     // Operations requiring live HSM state — skip with warning
        //     RecordedOperation::BackupDevice { .. }
        //     | RecordedOperation::RestoreDevice { .. }
        //     | RecordedOperation::ExportWrapped { .. }
        //     | RecordedOperation::ImportWrapped { .. } => {
        //         ui.display_warning(&format!("{} Skipping — requires interactive HSM state", step));
        //         Ok(())
        //     },
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