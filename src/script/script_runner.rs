use std::fmt::Display;
use std::{fmt, fs};
use std::path::Path;
use yubihsmrs::Session;
use yubihsmrs::object::ObjectType;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::auth::AuthenticationOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::ksp::KspOperations;
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::types::NewObjectSpec;
use crate::hsm_operations::wrap::WrapOperations;
use crate::script::types::{RecordedOperation, RecordableObjectSpec, SessionScript};
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;

#[derive(Clone, Debug, Default, clap::ValueEnum)]
pub enum ScriptMode {
    #[default]
    ExitOnError,
    ContinueOnError,
}

impl From<&String> for ScriptMode {
    fn from(s: &String) -> Self {
        match s.to_lowercase().as_str() {
            "exit_on_error" => ScriptMode::ExitOnError,
            "continue_on_error" => ScriptMode::ContinueOnError,
            other => {
                eprintln!("Unknown mode '{}', defaulting to 'exit_on_error'", other);
                ScriptMode::ExitOnError
            }
        }
    }
}

impl Display for ScriptMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ScriptMode::ExitOnError => write!(f, "exit_on_error"),
            ScriptMode::ContinueOnError => write!(f, "continue_on_error"),
        }
    }
}

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
        mode: &ScriptMode,
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

            let progress = ui.start_progress(Some(&step));

            match Self::execute(ui, session, op, &step) {
                Ok(()) => {
                    ui.display_success_message(&format!("{} Done", step));
                },
                Err(e) => {
                    let msg = format!("{} Failed: {}", step, e);
                    match mode {
                        ScriptMode::ExitOnError => {
                            ui.display_error_message(&msg);
                            return Err(e);
                        },
                        ScriptMode::ContinueOnError => {
                            ui.display_warning(&msg);
                            errors.push((i + 1, e.to_string()));
                        },
                    }
                },
            }

            ui.stop_progress(progress, None);
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
            RecordedOperation::GenerateObject(spec) => {
                let new_spec: NewObjectSpec = spec.into();
                match spec.object_type {
                    ObjectType::AsymmetricKey => { AsymmetricOperations.generate(session, &new_spec)?; },
                    ObjectType::SymmetricKey  => { SymmetricOperations.generate(session, &new_spec)?; },
                    ObjectType::WrapKey       => { WrapOperations.generate(session, &new_spec)?; },
                    other => return Err(MgmError::Error(format!("Cannot generate {:?}", other))),
                }
                Ok(())
            },

            // RecordedOperation::ImportObject { spec, data_b64 } => {
            //     if data_b64.iter().any(|d| d == "<REDACTED>") {
            //         return Err(MgmError::Error(format!(
            //             "Cannot replay import of {:?} 0x{:04x}: key data was redacted. Import manually.",
            //             spec.object_type, spec.id)));
            //     }
            //     let data: Vec<Vec<u8>> = data_b64.iter()
            //                                      .map(|b64| openssl::base64::decode_block(b64)
            //                                          .map_err(|e| MgmError::Error(format!("Invalid base64: {}", e))))
            //                                      .collect::<Result<Vec<_>, _>>()?;
            //     let mut new_spec: NewObjectSpec = spec.into();
            //     new_spec.data = data;
            //     match spec.object_type {
            //         ObjectType::AsymmetricKey     => { AsymmetricOperations.import(session, &new_spec)?; },
            //         ObjectType::SymmetricKey      => { SymmetricOperations.import(session, &new_spec)?; },
            //         ObjectType::WrapKey
            //         | ObjectType::PublicWrapKey    => { WrapOperations.import(session, &new_spec)?; },
            //         ObjectType::AuthenticationKey => { AuthenticationOperations.import(session, &new_spec)?; },
            //         other => return Err(MgmError::Error(format!("Cannot import {:?}", other))),
            //     }
            //     Ok(())
            // },

            RecordedOperation::DeleteObject { object_id, object_type } => {
                session.delete_object(*object_id, *object_type)?;
                Ok(())
            },

        //     RecordedOperation::CreateAuthKey { spec, auth_type, credential } => {
        //         let key_data: Vec<u8> = match auth_type.as_str() {
        //             "PasswordDerived" => {
        //                 let password = if credential == "<PASSWORD>" {
        //                     ui.get_password(
        //                         &format!("Enter password for auth key 0x{:04x} ('{}'):", spec.id, spec.label),
        //                         false)?
        //                 } else {
        //                     credential.to_string()
        //                 };
        //                 password.into_bytes()
        //             },
        //             "Ecp256" => {
        //                 let pems = crate::ui::helper_io::get_pem_from_file(credential)?;
        //                 let (_, _, value) = AsymmetricOperations::parse_asym_pem(pems[0].clone())?;
        //                 value
        //             },
        //             other => return Err(MgmError::Error(format!("Unknown auth type: '{}'", other))),
        //         };
        //         let mut new_spec: NewObjectSpec = spec.into();
        //         new_spec.data = vec![key_data];
        //         AuthenticationOperations.import(session, &new_spec)?;
        //         Ok(())
        //     },
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
        //     RecordedOperation::SignAttestationCert {
        //         attested_key_id, attesting_key_id, template_cert_file, output_file
        //     } => {
        //         let template = if let Some(path) = template_cert_file {
        //             let pems = crate::ui::helper_io::get_pem_from_file(path)?;
        //             Some(pems[0].clone())
        //         } else { None };
        //         let cert = AsymmetricOperations::get_attestation_cert(
        //             session, *attested_key_id, *attesting_key_id, template)?;
        //         if let Some(path) = output_file {
        //             fs::write(path, cert.to_string().as_bytes())
        //                 .map_err(|e| MgmError::Error(format!("Write failed: {}", e)))?;
        //         }
        //         Ok(())
        //     },
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