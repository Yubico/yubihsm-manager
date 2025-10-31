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

use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::path::Path;
use std::sync::LazyLock;

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectOrigin, ObjectType};
use yubihsmrs::Session;

use crate::backend::asym_utils::{AsymTypes, RSA_KEY_ALGORITHM, EC_KEY_ALGORITHM, RSA_KEY_CAPABILITIES, EC_KEY_CAPABILITIES,
                                 ED_KEY_CAPABILITIES, OPAQUE_CAPABILITIES, RSA_OAEP_ALGORITHM, AttestationTypes,
                                 get_asymmetric_objects, generate_asym_key, import_asym_object, get_asym_object_from_der,
                                 get_der_pubkey_as_pem, get_certificate, get_attestation_cert};
use crate::backend::common::{get_descriptors_from_handlers, get_new_object_note};
use crate::utils::{get_file_path, get_new_object_basics, get_operation_key, list_objects, print_object_properties,
                   read_input_bytes, read_input_string, read_pem_file, select_one_object, write_bytes_to_file,
                   delete_objects, select_delete_objects, fill_new_object_properties};

use crate::error::MgmError;
use crate::MAIN_STRING;

static ASYM_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Asymmetric keys", MAIN_STRING));

pub const RSA_KEY_CAPABILITIES: [ObjectCapability; 6] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

pub const EC_KEY_CAPABILITIES: [ObjectCapability; 4] = [
    ObjectCapability::SignEcdsa,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

pub const ED_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::SignEddsa,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

const OPAQUE_CAPABILITIES: [ObjectCapability; 1] = [
    ObjectCapability::ExportableUnderWrap];

pub const RSA_KEY_ALGORITHM: [ObjectAlgorithm; 3] = [
    ObjectAlgorithm::Rsa2048,
    ObjectAlgorithm::Rsa3072,
    ObjectAlgorithm::Rsa4096];

pub const EC_KEY_ALGORITHM: [ObjectAlgorithm; 8] = [
    ObjectAlgorithm::EcP224,
    ObjectAlgorithm::EcP256,
    ObjectAlgorithm::EcP384,
    ObjectAlgorithm::EcP521,
    ObjectAlgorithm::EcK256,
    ObjectAlgorithm::EcBp256,
    ObjectAlgorithm::EcBp384,
    ObjectAlgorithm::EcBp512];

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum AsymCommand {
    #[default]
    List,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    GetPublicKey,
    GetCertificate,
    Sign,
    Decrypt,
    DeriveEcdh,
    SignAttestationCert,
    ReturnToMainMenu,
    Exit,
}

impl Display for AsymCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsymCommand::List => write!(f, "List"),
            AsymCommand::GetKeyProperties => write!(f, "Print object properties"),
            AsymCommand::Generate => write!(f, "Generate"),
            AsymCommand::Import => write!(f, "Import"),
            AsymCommand::Delete => write!(f, "Delete"),
            AsymCommand::GetPublicKey => write!(f, "Get public key"),
            AsymCommand::GetCertificate => write!(f, "Get X509 certificate"),
            AsymCommand::Sign => write!(f, "Sign"),
            AsymCommand::Decrypt => write!(f, "Decrypt"),
            AsymCommand::DeriveEcdh => write!(f, "Derive ECDH"),
            AsymCommand::SignAttestationCert => write!(f, "Get attestation certificate"),
            AsymCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            AsymCommand::Exit => write!(f, "Exit"),
        }
    }
}

pub fn exec_asym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        println!("\n{}", *ASYM_STRING);

        let cmd = get_command(authkey)?;
        let res = match cmd {
            AsymCommand::List => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::List);
                list(session)
            },
            AsymCommand::GetKeyProperties => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::GetKeyProperties);
                print_key_properties(session)
            },
            AsymCommand::Generate => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::Generate);
                generate(session, authkey)
            },
            AsymCommand::Import => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::Import);
                import(session, authkey)
            },
            AsymCommand::Delete => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::Delete);
                delete(session)
            },
            AsymCommand::GetPublicKey => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::GetPublicKey);
                get_public_key(session)
            },
            AsymCommand::GetCertificate => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::GetCertificate);
                get_cert(session)
            },
            AsymCommand::Sign => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::Sign);
                sign(session, authkey)
            },
            AsymCommand::Decrypt => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::Decrypt);
                decrypt(session, authkey)
            },
            AsymCommand::DeriveEcdh => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::DeriveEcdh);
                derive_ecdh(session, authkey)
            },
            AsymCommand::SignAttestationCert => {
                println!("\n{} > {}\n", *ASYM_STRING, AsymCommand::SignAttestationCert);
                sign_attestation(session, authkey)
            },
            AsymCommand::ReturnToMainMenu => return Ok(()),
            AsymCommand::Exit => std::process::exit(0),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn get_command(authkey: &ObjectDescriptor) -> Result<AsymCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> = authkey.capabilities.clone().into_iter().collect();

    let mut commands = cliclack::select("").initial_value(AsymCommand::List);
    commands = commands.item(AsymCommand::List, AsymCommand::List, "");
    commands = commands.item(AsymCommand::GetKeyProperties, AsymCommand::GetKeyProperties, "");
    if capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) {
        commands = commands.item(AsymCommand::Generate, AsymCommand::Generate, "");
    }
    if capabilities.contains(&ObjectCapability::PutAsymmetricKey) {
        commands = commands.item(AsymCommand::Import, AsymCommand::Import, "");
    }
    if capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) ||
        capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands = commands.item(AsymCommand::Delete, AsymCommand::Delete, "");
    }
    commands = commands.item(AsymCommand::GetPublicKey, AsymCommand::GetPublicKey, "");
    if capabilities.contains(&ObjectCapability::GetOpaque) {
        commands = commands.item(AsymCommand::GetCertificate, AsymCommand::GetCertificate, "");
    }
    if HashSet::from([ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa]).intersection(&capabilities).count() > 0 {
        commands = commands.item(AsymCommand::Sign, AsymCommand::Sign, "");
    }
    if HashSet::from([
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep]).intersection(&capabilities).count() > 0 {
        commands = commands.item(AsymCommand::Decrypt, AsymCommand::Decrypt, "");
    }
    if capabilities.contains(&ObjectCapability::DeriveEcdh) {
        commands = commands.item(AsymCommand::DeriveEcdh, AsymCommand::DeriveEcdh, "");
    }
    if capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(AsymCommand::SignAttestationCert, AsymCommand::SignAttestationCert, "");
    }
    commands = commands.item(AsymCommand::ReturnToMainMenu, AsymCommand::ReturnToMainMenu, "");
    commands = commands.item(AsymCommand::Exit, AsymCommand::Exit, "");
    Ok(commands.interact()?)
}

fn get_all_asym_objects(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.
                              list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    keys.extend(session.
                           list_objects_with_filter(0, ObjectType::Opaque, "",ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    Ok(keys)
}

pub fn get_rsa_key_algo(size_in_bytes:u32) -> Result<ObjectAlgorithm, MgmError> {
    match size_in_bytes {
        256 => Ok(ObjectAlgorithm::Rsa2048),
        384 => Ok(ObjectAlgorithm::Rsa3072),
        512 => Ok(ObjectAlgorithm::Rsa4096),
        _ => {
            Err(MgmError::Error(format!("Unsupported RSA key size {}", (size_in_bytes * 8))))
        }
    }
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_asymmetric_objects(session, &[AsymTypes::Keys, AsymTypes::X509Certificates])?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(session, &get_all_asym_objects(session)?)?;
    delete_objects(session, &objects)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    match get_new_key_for_generation(authkey) {
        Ok(Some(new_key)) => {
            let mut spinner = cliclack::spinner();
            spinner.start("Generating key...");
            let id = generate_asym_key(session, &new_key)?;
            spinner.stop("");
            cliclack::log::success(
                format!("Generated asymmetric keypair with ID 0x{:04x} on the device", id))?;
            Ok(())
        },
        Ok(None) => return Ok(()),
        Err(e) => return Err(e),
    }
}

pub fn get_new_key_for_generation(authkey: &ObjectDescriptor) -> Result<Option<ObjectDescriptor>, MgmError> {
    let key_algo = cliclack::select("Select key type")
        .item(ObjectAlgorithm::Rsa2048, "RSA 2048", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa2048))
        .item(ObjectAlgorithm::Rsa3072, "RSA 3072", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa3072))
        .item(ObjectAlgorithm::Rsa4096, "RSA 4096", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa4096))
        .item(ObjectAlgorithm::EcP224, "EC P224", format!("curve: secp224r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP224))
        .item(ObjectAlgorithm::EcP256, "EC P256", format!("curve: secp256r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP256))
        .item(ObjectAlgorithm::EcP384, "EC P384", format!("curve: secp384r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP384))
        .item(ObjectAlgorithm::EcP521, "EC P521", format!("curve: secp521r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP521))
        .item(ObjectAlgorithm::EcK256, "EC K256", format!("curve: secp256k1. yubihsm-shell name: {}", ObjectAlgorithm::EcK256))
        .item(ObjectAlgorithm::EcBp256, "EC BP256", format!("curve: brainpool256r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp256))
        .item(ObjectAlgorithm::EcBp384, "EC BP384", format!("curve: brainpool384r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp384))
        .item(ObjectAlgorithm::EcBp512, "EC BP512", format!("curve: brainpool512r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp512))
        .item(ObjectAlgorithm::Ed25519, "ED 25519", format!("yubihsm-shell name: {}", ObjectAlgorithm::Ed25519))
        .interact()?;

    let mut new_key =
    if RSA_KEY_ALGORITHM.contains(&key_algo) {
        get_new_object_basics(authkey, ObjectType::AsymmetricKey, &RSA_KEY_CAPABILITIES, &[])?
    } else if EC_KEY_ALGORITHM.contains(&key_algo) {
        get_new_object_basics(authkey, ObjectType::AsymmetricKey, &EC_KEY_CAPABILITIES, &[])?
    } else {
        get_new_object_basics(authkey, ObjectType::AsymmetricKey, &ED_KEY_CAPABILITIES, &[])?
    };
    new_key.algorithm = key_algo;

    cliclack::note("Generating asymmetric key with:", get_new_object_note(&new_key))?;
    if cliclack::confirm("Generate key?").interact()? {
        return Ok(Some(new_key));
    }
    Ok(None)
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    match import_asym_key(session, authkey, get_file_path("Enter path to PEM file containing private key or X509Certificate: ")?) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
    }
}

pub fn import_asym_key(session: &Session, authkey: &ObjectDescriptor, filepath: String) -> Result<ObjectDescriptor, MgmError> {
    let pem = read_pem_file(filepath)?;
    let key_bytes = pem.contents();
    let (_type, _algo, _bytes) = get_asym_object_from_der(key_bytes)?;

    if _type != ObjectType::AsymmetricKey && _type != ObjectType::Opaque {
        return Err(MgmError::InvalidInput("PEM file contains neither a private key nor an X509 certificate".to_string()));
    }

    let mut new_key =
        if RSA_KEY_ALGORITHM.contains(&_algo) {
            get_new_object_basics(authkey, ObjectType::AsymmetricKey, &RSA_KEY_CAPABILITIES, &[])?
        } else if EC_KEY_ALGORITHM.contains(&_algo) {
            get_new_object_basics(authkey, ObjectType::AsymmetricKey, &EC_KEY_CAPABILITIES, &[])?
        } else if _algo == ObjectAlgorithm::Ed25519 {
            get_new_object_basics(authkey, ObjectType::AsymmetricKey, &ED_KEY_CAPABILITIES, &[])?
        } else if _algo == ObjectAlgorithm::OpaqueX509Certificate {
            get_new_object_basics(authkey, ObjectType::Opaque, &OPAQUE_CAPABILITIES, &[])?
        } else {
            cliclack::log::error("Unsupported key algorithm for import".to_string())?;
            return Err(MgmError::InvalidInput("Unsupported key algorithm for import".to_string()));
        };
    new_key.algorithm = _algo;

    cliclack::note("Importing asymmetric object with: ", get_new_object_note(&new_key))?;
    if cliclack::confirm("Import key?").interact()? {
        import_asym_object(session, &mut new_key, &_bytes)?;
        cliclack::log::success(
            format!("Imported object with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(new_key)
}

pub fn get_new_key_descriptor(authkey: &ObjectDescriptor, generate:bool, der_bytes:&[u8]) -> Result<(ObjectDescriptor, Vec<u8>), MgmError> {
    let mut new_key = ObjectDescriptor::new();
    let mut new_key_value = Vec::new();

    if generate {
        new_key.object_type = ObjectType::AsymmetricKey;
        new_key.algorithm = cliclack::select("Select key type")
            .item(ObjectAlgorithm::Rsa2048, "RSA 2048", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa2048))
            .item(ObjectAlgorithm::Rsa3072, "RSA 3072", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa3072))
            .item(ObjectAlgorithm::Rsa4096, "RSA 4096", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa4096))
            .item(ObjectAlgorithm::EcP224, "EC P224", format!("curve: secp224r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP224))
            .item(ObjectAlgorithm::EcP256, "EC P256", format!("curve: secp256r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP256))
            .item(ObjectAlgorithm::EcP384, "EC P384", format!("curve: secp384r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP384))
            .item(ObjectAlgorithm::EcP521, "EC P521", format!("curve: secp521r1. yubihsm-shell name: {}", ObjectAlgorithm::EcP521))
            .item(ObjectAlgorithm::EcK256, "EC K256", format!("curve: secp256k1. yubihsm-shell name: {}", ObjectAlgorithm::EcK256))
            .item(ObjectAlgorithm::EcBp256, "EC BP256", format!("curve: brainpool256r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp256))
            .item(ObjectAlgorithm::EcBp384, "EC BP384", format!("curve: brainpool384r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp384))
            .item(ObjectAlgorithm::EcBp512, "EC BP512", format!("curve: brainpool512r1. yubihsm-shell name: {}", ObjectAlgorithm::EcBp512))
            .item(ObjectAlgorithm::Ed25519, "ED 25519", format!("yubihsm-shell name: {}", ObjectAlgorithm::Ed25519))
            .interact()?;
    } else {
        let (_type, _algo, _bytes) = get_asym_object_from_der(der_bytes)?;

        if _type != ObjectType::AsymmetricKey && _type != ObjectType::Opaque {
            return Err(MgmError::InvalidInput("PEM file contains neither a private key nor an X509 certificate".to_string()));
        }
        new_key.algorithm = _algo;
        new_key.object_type = _type;
        new_key_value = _bytes;
    }

    if RSA_KEY_ALGORITHM.contains(&new_key.algorithm) {
        fill_new_object_properties(&mut new_key, authkey, &RSA_KEY_CAPABILITIES, &[])?;
    } else if EC_KEY_ALGORITHM.contains(&new_key.algorithm) {
        fill_new_object_properties(&mut new_key, authkey, &EC_KEY_CAPABILITIES, &[])?;
    } else if new_key.algorithm == ObjectAlgorithm::Ed25519 {
        fill_new_object_properties(&mut new_key, authkey, &ED_KEY_CAPABILITIES, &[])?;
    } else if new_key.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
        fill_new_object_properties(&mut new_key, authkey, &OPAQUE_CAPABILITIES, &[])?;
    } else {
        cliclack::log::error("Unsupported key algorithm for import".to_string())?;
        return Err(MgmError::InvalidInput("Unsupported key algorithm for import".to_string()));
    }
    Ok((new_key, new_key_value))
}

fn get_public_key(session: &Session) -> Result<(), MgmError> {
    let keys = get_asymmetric_objects(session, &[AsymTypes::Keys])?;
    let key = select_one_object(
        "Select key" , &get_descriptors_from_handlers(session, &keys)?)?;

    let pubkey = match session.get_pubkey(key.id, ObjectType::AsymmetricKey) {
        Ok(pk) => pk,
        Err(e) => {
            cliclack::log::error(format!("Failed to get public key for asymmetric key 0x{:04x}. {}",
                                         key.id, e))?;
            return Ok(())
        }
    };

    let pem_pubkey;
    let key_algo = pubkey.1;
    if RSA_KEY_ALGORITHM.contains(&key_algo) {
        let e = match BigNum::from_slice(&[0x01, 0x00, 0x01]) {
            Ok(bn) => bn,
            Err(err) => {
                cliclack::log::error(format!("Failed to construct exponent for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        let n = match BigNum::from_slice(pubkey.0.as_slice()) {
            Ok(bn) => bn,
            Err(err) => {
                cliclack::log::error(format!("Failed to construct n for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        let rsa_pubkey = match openssl::rsa::Rsa::from_public_components(n, e) {
            Ok(rsa) => rsa,
            Err(err) => {
                cliclack::log::error(format!("Failed to parse RSA public key for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        pem_pubkey = match rsa_pubkey.public_key_to_pem() {
            Ok(pem) => pem,
            Err(err) => {
                cliclack::log::error(format!("Failed to convert RSA public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };
    } else if EC_KEY_ALGORITHM.contains(&key_algo) {
        let nid = match key_algo {
            ObjectAlgorithm::EcP256 => Nid::X9_62_PRIME256V1,
            ObjectAlgorithm::EcK256 => Nid::SECP256K1,
            ObjectAlgorithm::EcP384 => Nid::SECP384R1,
            ObjectAlgorithm::EcP521 => Nid::SECP521R1,
            ObjectAlgorithm::EcP224 => Nid::SECP224R1,
            ObjectAlgorithm::EcBp256 => Nid::BRAINPOOL_P256R1,
            ObjectAlgorithm::EcBp384 => Nid::BRAINPOOL_P384R1,
            ObjectAlgorithm::EcBp512 => Nid::BRAINPOOL_P512R1,
            _ => unreachable!()
        };
        let ec_group = match EcGroup::from_curve_name(nid) {
            Ok(group) => group,
            Err(err) => {
                cliclack::log::error(format!("Failed to get EC group from key algorithm for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        let mut ctx = match BigNumContext::new() {
            Ok(bnc) => bnc,
            Err(err) => {
                cliclack::log::error(format!("Failed to create BigNumContext for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        let mut ec_pubkey_bytes: Vec<u8> = Vec::new();
        ec_pubkey_bytes.push(0x04);
        ec_pubkey_bytes.extend(pubkey.0);
        let ec_point = match EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx) {
            Ok(p) => p,
            Err(err) => {
                cliclack::log::error(format!("Failed to parse EC point for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        let ec_pubkey = match EcKey::from_public_key(&ec_group, &ec_point) {
            Ok(pk) => pk,
            Err(err) => {
                cliclack::log::error(format!("Failed to parse EC public key for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };

        pem_pubkey = match ec_pubkey.public_key_to_pem() {
            Ok(pem) => pem,
            Err(err) => {
                cliclack::log::error(format!("Failed to convert EC public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };
    } else if key_algo == ObjectAlgorithm::Ed25519 {
        let ed_pubkey = match PKey::public_key_from_raw_bytes(pubkey.0.as_slice(), pkey::Id::ED25519) {
            Ok(pk) => pk,
            Err(err) => {
                cliclack::log::error(format!("Failed to parse ED public key for key 0x{:04x}. {}", key.id, err))?;
                return Ok(());
            }
        };

        pem_pubkey = match ed_pubkey.public_key_to_pem() {
            Ok(pem) => pem,
            Err(err) => {
                cliclack::log::error(format!("Failed to convert ED public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                return Ok(())
            }
        };
    } else {
        cliclack::log::error(format!("Object 0x{:04x} is not an asymmetric key", key.id))?;
        return Ok(())
    }

    if let Ok(str) = String::from_utf8(pem_pubkey.clone()) { println!("{}\n", str) }

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.pubkey.pem", key.id);
        if let Err(err) = write_bytes_to_file(pem_pubkey, "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write public key 0x{:04x} to file. {}", key.id, err))?;
        }
    }
    Ok(())
}

fn get_cert(session: &Session) -> Result<(), MgmError> {
    let certs = get_asymmetric_objects(session, &[AsymTypes::X509Certificates])?;
    let cert = select_one_object(
        "Select certificates", &get_descriptors_from_handlers(session, &certs)?)?;

    let cert_pem = get_certificate(session, cert.id)?;
    if let Ok(str) = String::from_utf8(cert_pem.clone()) { println!("{}\n", str) }

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.cert.pem", cert.id);
        if let Err(err) = write_bytes_to_file(cert_pem, "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write certificate 0x{:04x} to file. {}", cert.id, err))?;
        }
    }
    Ok(())
}

pub fn get_hashed_bytes(algo: &ObjectAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
    match algo {
        ObjectAlgorithm::RsaPkcs1Sha1 |
        ObjectAlgorithm::RsaPssSha1 |
        ObjectAlgorithm::EcdsaSha1 |
        ObjectAlgorithm::RsaOaepSha1 => Ok(openssl::hash::hash(MessageDigest::sha1(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha256 |
        ObjectAlgorithm::RsaPssSha256 |
        ObjectAlgorithm::EcdsaSha256 |
        ObjectAlgorithm::RsaOaepSha256 => Ok(openssl::hash::hash(MessageDigest::sha256(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha384 |
        ObjectAlgorithm::RsaPssSha384 |
        ObjectAlgorithm::EcdsaSha384 |
        ObjectAlgorithm::RsaOaepSha384 => Ok(openssl::hash::hash(MessageDigest::sha384(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha512 |
        ObjectAlgorithm::RsaPssSha512 |
        ObjectAlgorithm::EcdsaSha512 |
        ObjectAlgorithm::RsaOaepSha512 => Ok(openssl::hash::hash(MessageDigest::sha512(), input)?.to_vec()),
        _ => Err(MgmError::InvalidInput("Algorithm does not contain hash component".to_string()))
    }
}

fn get_mgf1_algorithm(algo: &ObjectAlgorithm) -> Result<ObjectAlgorithm, MgmError> {
    match algo {
        ObjectAlgorithm::RsaOaepSha1 | ObjectAlgorithm::RsaPssSha1 => Ok(ObjectAlgorithm::Mgf1Sha1),
        ObjectAlgorithm::RsaOaepSha256 | ObjectAlgorithm::RsaPssSha256 => Ok(ObjectAlgorithm::Mgf1Sha256),
        ObjectAlgorithm::RsaOaepSha384 | ObjectAlgorithm::RsaPssSha384 => Ok(ObjectAlgorithm::Mgf1Sha384),
        ObjectAlgorithm::RsaOaepSha512 | ObjectAlgorithm::RsaPssSha512 => Ok(ObjectAlgorithm::Mgf1Sha512),
        _ => Err(MgmError::InvalidInput("Algorithm is not an RSA PSS or OAEP decryption algorithm".to_string())),
    }
}

fn sign(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let input = read_input_string("Enter data to sign or absolut path to binary file containing data to sign")?;

    let key = get_operation_key(
        session, authkey,
        [ObjectCapability::SignPkcs, ObjectCapability::SignPss, ObjectCapability::SignEcdsa, ObjectCapability::SignEddsa].to_vec().as_ref(),
        ObjectType::AsymmetricKey,
        &[])?;

    let sig_algo =
        if RSA_KEY_ALGORITHM.contains(&key.algorithm) {
        let mut algorithm = cliclack::select("Select RSA signing algorithm");
        if key.capabilities.contains(&ObjectCapability::SignPkcs) &&
            authkey.capabilities.contains(&ObjectCapability::SignPkcs) {
            algorithm = algorithm.item(ObjectAlgorithm::RsaPkcs1Sha1, "RSA-PKCS#1v1.5 with SHA1","");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPkcs1Sha256, "RSA-PKCS#1v1.5 with SHA256", "");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPkcs1Sha384, "RSA-PKCS#1v1.5 with SHA384", "");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPkcs1Sha512, "RSA-PKCS#1v1.5 with SHA512", "");
        }
        if key.capabilities.contains(&ObjectCapability::SignPss) &&
            authkey.capabilities.contains(&ObjectCapability::SignPss) {
            algorithm = algorithm.item(ObjectAlgorithm::RsaPssSha1, "RSA-PSS with SHA1", "");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPssSha256, "RSA-PSS with SHA256", "");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPssSha384, "RSA-PSS with SHA384", "");
            algorithm = algorithm.item(ObjectAlgorithm::RsaPssSha512, "RSA-PSS with SHA512", "");
        }
        algorithm.interact()?
    } else if EC_KEY_ALGORITHM.contains(&key.algorithm) {
        if key.capabilities.contains(&ObjectCapability::SignEcdsa) &&
            authkey.capabilities.contains(&ObjectCapability::SignEcdsa) {
            cliclack::select("Select ECDSA signing algorithm")
                .item(ObjectAlgorithm::EcdsaSha1, "ECDSA with SHA1", "")
                .item(ObjectAlgorithm::EcdsaSha256, "ECDSA with SHA256", "")
                .item(ObjectAlgorithm::EcdsaSha384, "ECDSA with SHA384", "")
                .item(ObjectAlgorithm::EcdsaSha512, "ECDSA with SHA512", "")
                .interact()?
        } else {
            return Err(MgmError::Error("Selected key has no ECDSA signing capabilities".to_string()))
        }
    } else if key.algorithm == ObjectAlgorithm::Ed25519 {
        if key.capabilities.contains(&ObjectCapability::SignEddsa) &&
            authkey.capabilities.contains(&ObjectCapability::SignEddsa) {
            ObjectAlgorithm::Ed25519
        } else {
            return Err(MgmError::Error("Selected key has no EDDSA signin capabilities".to_string()))
        }
    } else {
        return Err(MgmError::Error("Selected key has no asymmetric signing capabilities".to_string()))
    };

    let sig = crate::backend::asym_utils::sign(session, &key, &sig_algo, input.as_bytes())?;
    cliclack::log::success(format!("Signed data using {} and key 0x{:04x}:\n{}", sig_algo, key.id, hex::encode(&sig)))?;

    if cliclack::confirm("Write to binary file?").interact()? {
        if let Err(err) = write_bytes_to_file(sig, "", "data.sig") {
            cliclack::log::error(format!("Failed to write signature to file. {}", err))?;
        }
    }
    Ok(())
}

fn decrypt(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let enc = read_input_bytes(
        "Enter data to decrypt in Hex format or absolut path to file containing data to decrypt in binary format",
        true)?;

    let key = get_operation_key(
        session, authkey,
        [ObjectCapability::DecryptPkcs, ObjectCapability::DecryptOaep].to_vec().as_ref(),
        ObjectType::AsymmetricKey,
        &RSA_KEY_ALGORITHM)?;


    let mut algorithm = cliclack::select("Select RSA decryption algorithm");
    if key.capabilities.contains(&ObjectCapability::DecryptPkcs) &&
        authkey.capabilities.contains(&ObjectCapability::DecryptPkcs) {
        algorithm = algorithm.item(ObjectAlgorithm::RsaPkcs1Decrypt, "RSA-PKCS#1v1.5", "");
    }
    if key.capabilities.contains(&ObjectCapability::DecryptOaep) &&
        authkey.capabilities.contains(&ObjectCapability::DecryptOaep) {
        algorithm = algorithm.item(ObjectAlgorithm::RsaOaepSha1, "RSA-OAEP with SHA1", "");
        algorithm = algorithm.item(ObjectAlgorithm::RsaOaepSha256, "RSA-OAEP with SHA256", "");
        algorithm = algorithm.item(ObjectAlgorithm::RsaOaepSha384, "RSA-OAEP with SHA384", "");
        algorithm = algorithm.item(ObjectAlgorithm::RsaOaepSha512, "RSA-OAEP with SHA512", "");
    }
    let algorithm = algorithm.interact()?;

    let label = if RSA_OAEP_ALGORITHM.contains(&algorithm) {
        cliclack::input("Enter OAEP label in HEX format (Default is empty): ").default_input("").validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else {
                Ok(())
            }
        }).interact()?
    } else {
        String::new()
    };

    let data = crate::backend::asym_utils::decrypt(session, &key, &algorithm, label, enc.as_slice())?;
    cliclack::log::success(format!("Decrypted data using {} and key 0x{:04x}", algorithm, key.id))?;

    if let Ok(data_str) = std::str::from_utf8(data.as_slice()) {
        cliclack::log::success(format!("Plain text data:\n{}", data_str))?;
    }

    if cliclack::confirm("Write to binary file?").interact()? {
        if let Err(err) = write_bytes_to_file(data, "", "data.dec") {
            cliclack::log::error(format!("Failed to write decrypted data to file. {}", err))?;
        }
    }

    Ok(())
}

fn derive_ecdh(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let hsm_key = get_operation_key(
        session, authkey,
        [ObjectCapability::DeriveEcdh].to_vec().as_ref(),
        ObjectType::AsymmetricKey,
        &EC_KEY_ALGORITHM)?;

    let peer_key = read_pem_file(get_file_path("Enter path to PEM file containing the peer public key: ")?)?;
    let shared_secret = crate::backend::asym_utils::derive_ecdh(session, &hsm_key, peer_key)?;
    cliclack::log::success(hex::encode(shared_secret))?;

    Ok(())
}

fn sign_attestation(session: &Session, authkey:&ObjectDescriptor) -> Result<(), MgmError> {
    if !authkey.capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        return Err(MgmError::Error("User does not have signing attestation certificates capabilities".to_string()));
    }

    let keys = session.list_objects_with_filter(
        0,
        ObjectType::AsymmetricKey,
        "",
        ObjectAlgorithm::ANY,
        &Vec::new())?;
    if keys.is_empty() {
        return Err(MgmError::Error("There are no asymmetric keys to attest".to_string()));
    }

    let cert_pem =
        match cliclack::select("")
            .item(AttestationTypes::DeviceSigned, AttestationTypes::DeviceSigned, "")
            .item(AttestationTypes::SelfSigned, AttestationTypes::SelfSigned, "")
            .item(AttestationTypes::AsymSigned, AttestationTypes::AsymSigned, "").interact()? {

                AttestationTypes::DeviceSigned => {
                    let mut keys = get_descriptors_from_handlers(session, &keys)?;
                    keys.retain(|k| k.origin == ObjectOrigin::Generated);
                    let attested_key = select_one_object("Select key to attest", &keys)?;
                    get_attestation_cert(session, attested_key.id, 0, &[])?
                },
                AttestationTypes::SelfSigned => {
                    let mut keys = get_descriptors_from_handlers(session, &keys)?;
                    keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate) && k.origin == ObjectOrigin::Generated);
                    let key = select_one_object("Select key to self-attest", &keys)?;
                    get_attestation_cert(session, key.id, key.id, &[])?
                },
                AttestationTypes::AsymSigned => {
                    let keys = get_descriptors_from_handlers(session, &keys)?;

                    let mut attested_keys = keys.clone();
                    attested_keys.retain(|k| k.origin == ObjectOrigin::Generated);
                    let attested_key = select_one_object("Select key to attest", &attested_keys)?;

                    let mut attesting_keys = keys;
                    attesting_keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
                    let attesting_key = select_one_object("Select attesting key", &attesting_keys)?;

                    // let template_cert = get_attestation_template_cert()?;
                    let template_cert: String = cliclack::input("Enter path to PEM file containing an X509Certificate to use as a template for the attestation certificate. Template certificate will be deleted after successful execution: ").required(false).placeholder("Empty default is using device attestation as certificate template").validate(|input: &String| {
                        if !input.is_empty() && !Path::new(input).exists() {
                            Err("File does not exist")
                        } else {
                            Ok(())
                        }
                    }).interact()?;
                    let template_cert = if !template_cert.is_empty() {
                        read_pem_file(template_cert)?.contents().to_vec()
                    } else {
                        Vec::new()
                    };
                    get_attestation_cert(session, attested_key.id, attesting_key.id, template_cert.as_slice())?
                }
        };

    if let Ok(str) = String::from_utf8(cert_pem.clone()) { println!("{}\n", str) }

    if cliclack::confirm("Write to file?").interact()? {
        if let Err(err) = write_bytes_to_file(cert_pem, "", "attestation_cert.pem") {
            cliclack::log::error(
                format!("Failed to write attestation certificate to file. {}", err))?;
        }
    }
    Ok(())
}