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

use std::path::Path;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectOrigin, ObjectType};
use yubihsmrs::Session;
use crate::ui::cmd_utils::{print_menu_headers, print_object_properties, select_delete_objects, select_one_object};
use crate::backend::types::YhCommand;
use crate::ui::cmd_utils::select_command;
use crate::backend::wrap::WrapOps;
use crate::ui::cmd_utils::select_algorithm;
use crate::backend::object_ops::Deletable;
use crate::ui::cmd_utils::print_failed_delete;
use crate::backend::asym::AttestationType;
use crate::backend::object_ops::Importable;
use crate::backend::types::ImportObjectSpec;
use crate::backend::object_ops::Generatable;
use crate::backend::types::ObjectSpec;
use crate::ui::cmd_utils::fill_object_spec;
use crate::ui::cmd_utils::list_objects;
use crate::backend::asym::AsymmetricType;
use crate::backend::asym::AsymOps;
use crate::backend::object_ops::Obtainable;

use crate::ui::io_utils::{get_file_path,
                          read_input_bytes, read_input_string, read_pem_from_file,
                          write_bytes_to_file};

use crate::backend::error::MgmError;

static ASYM_HEADER: &str = "Asymmetric keys";

pub fn exec_asym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        print_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER]);

        let cmd = select_command(&AsymOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, ASYM_HEADER, cmd.label]);

        let res = match cmd.command {
            YhCommand::List => list(session),
            YhCommand::GetKeyProperties => print_key_properties(session),
            YhCommand::Generate => generate(session, authkey),
            YhCommand::Import => import(session, authkey),
            YhCommand::Delete => delete(session),
            YhCommand::GetPublicKey => get_public_key(session, ObjectType::AsymmetricKey),
            YhCommand::GetCertificate => get_cert(session),
            YhCommand::Sign => sign(session, authkey),
            YhCommand::Decrypt => decrypt(session, authkey),
            YhCommand::DeriveEcdh => derive_ecdh(session, authkey),
            YhCommand::SignAttestationCert => sign_attestation(session, authkey),
            YhCommand::ReturnToMainMenu => return Ok(()),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    let types = cliclack::multiselect("Select type to list")
        .initial_values([AsymmetricType::Key, AsymmetricType::X509Certificate].to_vec())
        .required(false)
        .item(AsymmetricType::Key, AsymmetricType::Key, "")
        .item(AsymmetricType::X509Certificate, AsymmetricType::X509Certificate, "")
        .interact()?;
    list_objects(&AsymOps::get_asymmetric_objects(session, &types)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(&AsymOps::get_asymmetric_objects(session, &[AsymmetricType::Key, AsymmetricType::X509Certificate])?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(&AsymOps.get_all_objects(session)?)?;
    let failed = AsymOps.delete_multiple(session, &objects);
    print_failed_delete(&failed)
}

pub fn fill_asym_spec(authkey: &ObjectDescriptor, spec: &mut ObjectSpec) -> Result<(), MgmError> {
    if spec.algorithm == ObjectAlgorithm::ANY {
        let mut key_algo = cliclack::select("Select key type");
        for algo in &AsymOps::get_object_algorithms() {
            key_algo = key_algo.item(algo.algorithm(), algo.label(), algo.description());
        }
        spec.algorithm = key_algo.interact()?;
    }
    fill_object_spec(authkey, spec, &AsymOps::get_object_capabilities(&spec.algorithm), &[])?;
    Ok(())
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key_algo = select_algorithm("Select key algorithm", &AsymOps::get_object_algorithms(), None)?;

    let mut new_key = ObjectSpec::empty();
    new_key.algorithm = key_algo;
    fill_object_spec(authkey, &mut new_key, &AsymOps::get_object_capabilities(&key_algo), &[])?;

    cliclack::note("Generating asymmetric key with:", new_key.to_string())?;
    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating key...");
        new_key.id = AsymOps.generate(session, &new_key)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated asymmetric keypair with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

pub fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let filepath = get_file_path("Enter path to PEM file containing private key or X509Certificate: ")?;
    let pem = read_pem_from_file(filepath)?;
    let (_type, _algo, _bytes) = AsymOps::parse_asym_pem(pem)?;

    if _type != ObjectType::AsymmetricKey && _type != ObjectType::Opaque {
        return Err(MgmError::InvalidInput("PEM file contains neither a private key nor an X509 certificate".to_string()));
    }

    let mut new_key = ObjectSpec::empty();
    new_key.algorithm = _algo;
    fill_object_spec(authkey, &mut new_key, &AsymOps::get_object_capabilities(&_algo), &[])?;
    let new_key = ImportObjectSpec {
        object: new_key,
        data: vec![_bytes],
    };

    cliclack::note("Importing asymmetric object with: ", new_key.object.to_string())?;
    if cliclack::confirm("Import key?").interact()? {
        let id = AsymOps.import(session, &new_key)?;
        // import_asym_object(session, &mut new_key, &_bytes)?;
        cliclack::log::success(
            format!("Imported object with ID 0x{:04x} on the device", id))?;
    }
    Ok(())
}

pub fn get_public_key(session: &Session, object_type: ObjectType) -> Result<(), MgmError> {
    let keys = if object_type == ObjectType::AsymmetricKey {
        AsymOps::get_asymmetric_objects(session, &[AsymmetricType::Key])?
    } else if object_type == ObjectType::WrapKey {
        WrapOps::get_rsa_wrapkeys(session)?
    } else {
        return Err(MgmError::InvalidInput("Object type is not asymmetric key or public key".to_string()));
    };

    let key = select_one_object(
        "Select key" , &keys)?;


    let pubkey = AsymOps::get_pubkey(session, key.id, key.object_type)?;
    println!("{}\n",pubkey);

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.pubkey.pem", key.id);
        if let Err(err) = write_bytes_to_file(&pubkey.to_string().into_bytes(), "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write public key 0x{:04x} to file. {}", key.id, err))?;
        }
    }
    Ok(())
}

fn get_cert(session: &Session) -> Result<(), MgmError> {
    let certs = AsymOps::get_asymmetric_objects(session, &[AsymmetricType::X509Certificate])?;
    let cert = select_one_object(
        "Select certificates", &certs)?;

    let cert_pem = AsymOps::get_certificate(session, cert.id)?;
    println!("{}\n", cert_pem);

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.cert.pem", cert.id);
        if let Err(err) = write_bytes_to_file(&cert_pem.to_string().into_bytes(), "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write certificate 0x{:04x} to file. {}", cert.id, err))?;
        }
    }
    Ok(())
}

fn sign(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let input = read_input_string("Enter data to sign or absolut path to binary file containing data to sign")?;

    let key = select_one_object(
        "Select signing key", &AsymOps::get_signing_keys(session, authkey)?)?;

    let sign_algo = select_algorithm("Select RSA signing algorithm", &AsymOps::get_signing_algorithms(authkey, &key), None)?;
    let sig = AsymOps::sign(session, key.id, &sign_algo, input.as_bytes())?;
    cliclack::log::success(format!("Signed data using {} and key 0x{:04x}:\n{}", sign_algo, key.id, hex::encode(&sig)))?;

    if cliclack::confirm("Write to binary file?").interact()? {
        if let Err(err) = write_bytes_to_file(&sig, "", "data.sig") {
            cliclack::log::error(format!("Failed to write signature to file. {}", err))?;
        }
    }
    Ok(())
}

fn decrypt(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let enc = read_input_bytes(
        "Enter data to decrypt in Hex format or absolut path to file containing data to decrypt in binary format",
        true)?;

    let key = select_one_object(
        "Select decryption key", &AsymOps::get_decryption_keys(session, authkey)?)?;
    let algorithm = select_algorithm("Select RSA decryption algorithm", &AsymOps::get_decryption_algorithms(authkey, &key), None)?;
    let data = AsymOps::decrypt(session, key.id, &algorithm, enc.as_slice())?;
    cliclack::log::success(format!("Decrypted data using {} and key 0x{:04x}", algorithm, key.id))?;

    if let Ok(data_str) = std::str::from_utf8(data.as_slice()) {
        cliclack::log::success(format!("Plain text data:\n{}", data_str))?;
    }

    if cliclack::confirm("Write to binary file?").interact()? {
        if let Err(err) = write_bytes_to_file(&data, "", "data.dec") {
            cliclack::log::error(format!("Failed to write decrypted data to file. {}", err))?;
        }
    }

    Ok(())
}

fn derive_ecdh(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let hsm_key = select_one_object(
        "Select ECDH key", &AsymOps::get_derivation_keys(session, authkey)?)?;

    let peer_key = read_pem_from_file(get_file_path("Enter path to PEM file containing the peer public key: ")?)?;
    let shared_secret = AsymOps::derive_ecdh(session, &hsm_key, peer_key)?;
    cliclack::log::success(hex::encode(shared_secret))?;

    Ok(())
}

fn sign_attestation(session: &Session, authkey:&ObjectDescriptor) -> Result<(), MgmError> {
    if !authkey.capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        return Err(MgmError::Error("User does not have signing attestation certificates capabilities".to_string()));
    }

    let mut keys = AsymOps::get_asymmetric_objects(session, &[AsymmetricType::Key])?;
    if keys.is_empty() {
        return Err(MgmError::Error("There are no asymmetric keys to attest".to_string()));
    }

    let attest_type = cliclack::select("")
        .item(AttestationType::DeviceSigned, AttestationType::DeviceSigned, "")
        .item(AttestationType::SelfSigned, AttestationType::SelfSigned, "")
        .item(AttestationType::AsymSigned, AttestationType::AsymSigned, "")
        .interact()?;

    let mut attested_keys = keys.clone();
    attested_keys.retain(|k| k.origin == ObjectOrigin::Generated);

    let (attested_key, attesting_key, template_cert) = match attest_type {
        AttestationType::DeviceSigned => {
            let key = select_one_object("Select key to attest", &attested_keys)?;
            (key.id, 0, None)
        },
        AttestationType::SelfSigned => {
            attested_keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
            let key = select_one_object("Select key to self-attest", &attested_keys)?;
            (key.id, key.id, None)
        },
        AttestationType::AsymSigned => {
            let attested_key = select_one_object("Select key to attest", &attested_keys)?;

            keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
            let attesting_key = select_one_object("Select attesting key", &keys)?;

            let template_file: String = cliclack::input("Enter path to PEM file containing an X509Certificate to use as a template for the attestation certificate. Template certificate will be deleted after successful execution: ").required(false).placeholder("Empty default is using device attestation as certificate template").validate(|input: &String| {
                if !input.is_empty() && !Path::new(input).exists() {
                    Err("File does not exist")
                } else {
                    Ok(())
                }
            }).interact()?;

            let template_cert = if template_file.is_empty() {
                None
            } else {
                Some(read_pem_from_file(template_file)?)
            };
            (attested_key.id, attesting_key.id, template_cert)
        }
    };

    let cert = AsymOps::get_attestation_cert(session, attested_key, attesting_key, template_cert)?;
    println!("{}\n", cert);

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.attestation_cert.pem", attested_key);
        if let Err(err) = write_bytes_to_file(&cert.to_string().into_bytes(), "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write attestation certificate to file. {}", err))?;
        }
    }
    Ok(())
}