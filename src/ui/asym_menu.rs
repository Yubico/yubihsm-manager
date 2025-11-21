/*
 * Copyright 2025 Yubico AB
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

use yubihsmrs::object::{ObjectCapability, ObjectDescriptor, ObjectOrigin, ObjectType};
use yubihsmrs::Session;
use crate::ui::utils::{generate_object, import_object, list_objects, delete_objects, display_object_properties};
use crate::ui::utils::{display_menu_headers, get_hex_or_bytes_from_file, get_pem_from_file, get_string_or_bytes_from_file, write_bytes_to_file};
use crate::traits::ui_traits::YubihsmUi;
use crate::traits::backend_traits::YubihsmOperations;
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::types::{SelectionItem, MgmCommandType};
use crate::backend::wrap::WrapOps;
use crate::backend::asym::{AttestationType, AsymOps};

static ASYM_HEADER: &str = "Asymmetric keys";

pub struct AsymmetricMenu;

impl AsymmetricMenu {
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {

            display_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER],
                                 "Asymmetric key operations allow you to manage and use asymmetric keys and X509 certificates stored on the YubiHSM")?;

            let cmd = YubihsmUi::select_command(&Cmdline, &AsymOps.get_authorized_commands(authkey))?;
            display_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&AsymOps, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&AsymOps, session),
                MgmCommandType::Generate => generate_object(&AsymOps, session, authkey, ObjectType::AsymmetricKey),
                MgmCommandType::Import => Self::import(session, authkey),
                MgmCommandType::Delete => delete_objects(&AsymOps, session, &AsymOps.get_all_objects(session)?),
                MgmCommandType::GetPublicKey => Self::get_public_key(session, ObjectType::AsymmetricKey),
                MgmCommandType::GetCertificate => Self::get_cert(session),
                MgmCommandType::Sign => Self::sign(session, authkey),
                MgmCommandType::Decrypt => Self::decrypt(session, authkey),
                MgmCommandType::DeriveEcdh => Self::derive_ecdh(session, authkey),
                MgmCommandType::SignAttestationCert => Self::sign_attestation(session, authkey),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
            }
        }
    }

    pub fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let filepath = YubihsmUi::get_pem_filepath(
            &Cmdline,
            "Enter path to PEM file containing private key or X509Certificate:",
            true,
            None)?;
        let pem = get_pem_from_file(&filepath)?[0].clone();
        let (_type, _algo, _bytes) = AsymOps::parse_asym_pem(pem)?;

        if _type != ObjectType::AsymmetricKey && _type != ObjectType::Opaque {
            return Err(MgmError::InvalidInput("PEM file contains neither a private key nor an X509 certificate".to_string()));
        }

        import_object(&AsymOps, session, authkey, _type, _algo, [_bytes].to_vec())
    }

    pub fn get_public_key(session: &Session, object_type: ObjectType) -> Result<(), MgmError> {
        let keys = if object_type == ObjectType::AsymmetricKey {
            AsymOps::get_asymmetric_objects(session, &[ObjectType::AsymmetricKey])?
        } else if object_type == ObjectType::WrapKey {
            WrapOps::get_rsa_wrapkeys(session)?
        } else {
            return Err(MgmError::InvalidInput(
                format!("Retrieving public key is not applicable for object type {}", object_type)));
        };

        let key = YubihsmUi::select_one_object(&Cmdline,
                                               &keys, Some("Select key"))?;

        let pubkey = AsymOps::get_pubkey(session, key.id, key.object_type)?;
        YubihsmUi::display_success_message(&Cmdline, pubkey.to_string().as_str())?;

        if YubihsmUi::get_confirmation(&Cmdline, "Write to file?")? {
            let filename = format!("0x{:04x}.pubkey.pem", key.id);
            if let Err(err) = write_bytes_to_file(&pubkey.to_string().into_bytes(), filename.as_str(), None) {
                YubihsmUi::display_error_message(&Cmdline,
                                                 format!("Failed to write public key 0x{:04x} to file. {}", key.id, err).as_str())?;
            }
        }
        Ok(())
    }

    fn get_cert(session: &Session) -> Result<(), MgmError> {
        let certs = AsymOps::get_asymmetric_objects(session, &[ObjectType::Opaque])?;
        let cert = YubihsmUi::select_one_object(&Cmdline,
                                                &certs, Some("Select certificate(s):"))?;

        let cert_pem = AsymOps::get_certificate(session, cert.id)?;
        YubihsmUi::display_success_message(&Cmdline, cert_pem.to_string().as_str())?;

        if YubihsmUi::get_confirmation(&Cmdline, "Write to file?")? {
            let filename = format!("0x{:04x}.cert.pem", cert.id);
            if let Err(err) = write_bytes_to_file(&cert_pem.to_string().into_bytes(), filename.as_str(), None) {
                YubihsmUi::display_error_message(&Cmdline,
                                                 format!("Failed to write certificate 0x{:04x} to file. {}", cert.id, err).as_str())?;
            }
        }
        Ok(())
    }

    fn sign(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let input = YubihsmUi::get_string_input(
            &Cmdline, "Enter data to sign or absolut path to file containing data to sign", true)?;
        let input = get_string_or_bytes_from_file(input)?;

        let key = YubihsmUi::select_one_object(
            &Cmdline,
            &AsymOps::get_signing_keys(session, authkey)?,
            Some("Select signing key"))?;

        let sign_algo = YubihsmUi::select_algorithm(
            &Cmdline, &AsymOps::get_signing_algorithms(authkey, &key), None, Some("Select RSA signing algorithm"))?;
        let sig = AsymOps::sign(session, key.id, &sign_algo, &input)?;
        YubihsmUi::display_success_message(&Cmdline, format!("Signed data using {} and key 0x{:04x}:\n{}", sign_algo, key.id, hex::encode(&sig)).as_str())?;

        if YubihsmUi::get_confirmation(&Cmdline, "Write to binary file?")? {
            if let Err(err) = write_bytes_to_file(&sig, "data.sig", None) {
                YubihsmUi::display_error_message(&Cmdline, format!("Failed to write signature to file. {}", err).as_str())?;
            }
        }
        Ok(())
    }

    fn decrypt(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let enc = YubihsmUi::get_string_input(
            &Cmdline, "Enter data to decrypt in Hex format or absolut path to binary file", true)?;
        let enc = get_hex_or_bytes_from_file(enc)?;

        let key = YubihsmUi::select_one_object(
            &Cmdline,
            &AsymOps::get_decryption_keys(session, authkey)?,
            Some("Select decryption key"))?;
        let algorithm = YubihsmUi::select_algorithm(
            &Cmdline,
            &AsymOps::get_decryption_algorithms(authkey, &key),
            None,
            Some("Select RSA decryption algorithm"))?;

        let data = AsymOps::decrypt(session, key.id, &algorithm, &enc)?;
        YubihsmUi::display_success_message(&Cmdline, format!("Decrypted data using {} and key 0x{:04x}", algorithm, key.id).as_str())?;

        if let Ok(data_str) = std::str::from_utf8(data.as_slice()) {
            YubihsmUi::display_success_message(&Cmdline, format!("Plain text data:\n{}", data_str).as_str())?;
        }

        if YubihsmUi::get_confirmation(&Cmdline, "Write to binary file?")? {
            if let Err(err) = write_bytes_to_file(&data, "data.dec", None) {
                YubihsmUi::display_error_message(&Cmdline, format!("Failed to write decrypted data to file. {}", err).as_str())?;
            }
        }
        Ok(())
    }

    fn derive_ecdh(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let hsm_key = YubihsmUi::select_one_object(
            &Cmdline,
            &AsymOps::get_derivation_keys(session, authkey)?,
            Some("Select ECDH key"))?;

        let peer_key = YubihsmUi::get_public_eckey_filepath(
            &Cmdline,
            "Enter path to PEM file containing the peer public key:")?;
        let peer_key = get_pem_from_file(&peer_key)?[0].clone();

        let shared_secret = AsymOps::derive_ecdh(session, &hsm_key, peer_key)?;
        YubihsmUi::display_success_message(&Cmdline, hex::encode(shared_secret).as_str())?;

        Ok(())
    }

    fn sign_attestation(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        if !authkey.capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
            return Err(MgmError::Error("User does not have signing attestation certificates capabilities".to_string()));
        }

        let mut keys = AsymOps::get_asymmetric_objects(session, &[ObjectType::AsymmetricKey])?;
        if keys.is_empty() {
            return Err(MgmError::Error("There are no asymmetric keys to attest".to_string()));
        }

        let attest_type = SelectionItem::get_items(&[
            AttestationType::DeviceSigned,
            AttestationType::SelfSigned,
            AttestationType::AsymSigned,
        ]);
        let attest_type = YubihsmUi::select_one_item(
            &Cmdline,
            &attest_type,
            None,
            Some("Select attestation type"))?;

        let mut attested_keys = keys.clone();
        attested_keys.retain(|k| k.origin == ObjectOrigin::Generated);

        let (attested_key, attesting_key, template_cert) = match attest_type {
            AttestationType::DeviceSigned => {
                let key = YubihsmUi::select_one_object(
                    &Cmdline,
                    &attested_keys,
                    Some("Select key to attest"))?;
                (key.id, 0, None)
            },
            AttestationType::SelfSigned => {
                attested_keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
                let key = YubihsmUi::select_one_object(
                    &Cmdline,
                    &attested_keys,
                    Some("Select key to self-attest"))?;
                (key.id, key.id, None)
            },
            AttestationType::AsymSigned => {
                let attested_key = YubihsmUi::select_one_object(
                    &Cmdline,
                    &attested_keys,
                    Some("Select key to attest"))?;

                keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
                let attesting_key = YubihsmUi::select_one_object(
                    &Cmdline,
                    &keys,
                    Some("Select attesting key"))?;

                let template_file = YubihsmUi::get_certificate_filepath(
                    &Cmdline,
                    "Enter path to PEM file containing an X509Certificate to use as a template for the attestation certificate. Template certificate will be deleted after successful execution:",
                    false,
                    Some("Empty default is using device attestation as certificate template"))?;
                let template_cert = if template_file.is_empty() {
                    None
                } else {
                    Some(get_pem_from_file(&template_file)?[0].clone())
                };

                (attested_key.id, attesting_key.id, template_cert)
            }
        };

        let cert = AsymOps::get_attestation_cert(session, attested_key, attesting_key, template_cert)?;
        YubihsmUi::display_success_message(&Cmdline, cert.to_string().as_str())?;

        if YubihsmUi::get_confirmation(&Cmdline, "Write to file?")? {
            let filename = format!("0x{:04x}.attestation_cert.pem", attested_key);
            if let Err(err) = write_bytes_to_file(&cert.to_string().into_bytes(), filename.as_str(), None) {
                YubihsmUi::display_error_message(&Cmdline,
                                                 format!("Failed to write attestation certificate to file. {}", err).as_str())?;
            }
        }
        Ok(())
    }
}