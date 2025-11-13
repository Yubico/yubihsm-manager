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
use crate::utils::print_menu_headers;
use crate::backend::types::YhCommand;
use crate::utils::select_command;
use crate::backend::wrap::WrapOps;
use crate::utils::select_algorithm;
use crate::backend::object_ops::Deletable;
use crate::utils::print_failed_delete;
use crate::backend::asym::AttestationType;
use crate::backend::object_ops::Importable;
use crate::backend::types::ImportObjectSpec;
use crate::backend::object_ops::Generatable;
use crate::backend::types::ObjectSpec;
use crate::utils::fill_object_spec;
use crate::utils::{list_objects, print_object_properties};
use crate::backend::asym::AsymmetricType;
use crate::backend::asym::AsymOps;
use crate::backend::object_ops::Obtainable;

use crate::utils::{get_file_path,
                   read_input_bytes, read_input_string, read_pem_from_file, select_one_object, write_bytes_to_file,
                   select_delete_objects};

use crate::error::MgmError;

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
            key_algo = key_algo.item(algo.algorithm, algo.label, algo.description);
        }
        spec.algorithm = key_algo.interact()?;
    }
    fill_object_spec(authkey, spec, &AsymOps::get_object_capabilities(&spec.algorithm), &[])?;
    Ok(())
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
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

    let pubkey = AsymOps::get_pubkey_pem(session, key.id, key.object_type)?;
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