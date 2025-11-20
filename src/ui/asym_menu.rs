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
use crate::traits::ui_traits::YubihsmUi;
use crate::traits::backend_traits::YubihsmOperations;
use crate::ui::utils::{display_menu_headers, get_hex_or_bytes_from_file, get_pem_from_file, get_string_or_bytes_from_file, write_bytes_to_file, delete_objects, display_object_properties};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::types::{SelectionItem, MgmCommandType, ImportObjectSpec, ObjectSpec};
use crate::backend::wrap::WrapOps;
use crate::backend::asym::{AttestationType, AsymOps};

static ASYM_HEADER: &str = "Asymmetric keys";

pub fn exec_asym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        display_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER],
            "Asymmetric key operations allow you to manage and use asymmetric keys and X509 certificates stored on the YubiHSM")?;

        let cmd = YubihsmUi::select_command(&Cmdline, &AsymOps.get_authorized_commands(authkey))?;
        display_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER, cmd.label], cmd.description)?;

        let res = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => print_key_properties(session),
            MgmCommandType::Generate => generate(session, authkey),
            MgmCommandType::Import => import(session, authkey),
            MgmCommandType::Delete => delete(session),
            MgmCommandType::GetPublicKey => get_public_key(session, ObjectType::AsymmetricKey),
            MgmCommandType::GetCertificate => get_cert(session),
            MgmCommandType::Sign => sign(session, authkey),
            MgmCommandType::Decrypt => decrypt(session, authkey),
            MgmCommandType::DeriveEcdh => derive_ecdh(session, authkey),
            MgmCommandType::SignAttestationCert => sign_attestation(session, authkey),
            MgmCommandType::ReturnToMainMenu => return Ok(()),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    YubihsmUi::display_objects_basic(&Cmdline, &AsymOps.get_all_objects(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&AsymOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, &AsymOps.get_all_objects(session)?)
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    let mut new_key = ObjectSpec::empty();
    new_key.object_type = ObjectType::AsymmetricKey;
    new_key.algorithm = YubihsmUi::select_algorithm(
        &Cmdline,
        &AsymOps.get_generation_algorithms(),
        None,
        Some("Select key algorithm"))?;
    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &AsymOps.get_applicable_capabilities(authkey, None, Some(new_key.algorithm))?,
        &[],
        None)?;

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Generating asymmetric key with:", &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Key is not generated")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.id = AsymOps.generate(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Generated asymmetric keypair with ID 0x{:04x} on the YubiHSM", new_key.id).as_str())?;
    Ok(())
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

    let mut new_key = ImportObjectSpec::empty();
    new_key.object.object_type = _type;
    new_key.object.algorithm = _algo;
    new_key.data.push(_bytes);
    new_key.object.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.object.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.object.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.object.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &AsymOps.get_applicable_capabilities(authkey, None, Some(new_key.object.algorithm))?,
        &[],
        Some("Select object capabilities"))?;

    if !YubihsmUi::get_note_confirmation(
        &Cmdline,
        "Importing asymmetric object with:",
        &new_key.object.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Object is not imported")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.object.id = AsymOps.import(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object.object_type, new_key.object.id).as_str())?;
    Ok(())
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

fn sign_attestation(session: &Session, authkey:&ObjectDescriptor) -> Result<(), MgmError> {
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