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
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::sync::LazyLock;
use base64::Engine;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectOrigin, ObjectType};
use yubihsmrs::Session;

use rsa::{RsaPublicKey, traits::PublicKeyParts, traits::PrivateKeyParts, pkcs1::{DecodeRsaPrivateKey}};
use p224::{ecdsa::VerifyingKey as VerifyingKeyP224, EncodedPoint as EncodedPointP224};
use k256::{ecdsa::VerifyingKey as VerifyingKeyK256, EncodedPoint as EncodedPointK256};
use p256::{ecdsa::VerifyingKey as VerifyingKeyP256, EncodedPoint as EncodedPointP256};
use p384::{ecdsa::VerifyingKey as VerifyingKeyP384, EncodedPoint as EncodedPointP384};
use p521::{PublicKey as PublicKeyP521, EncodedPoint as EncodedPointP521};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use pkcs8::der::Decode;
use spki::{der::pem::LineEnding, EncodePublicKey, SubjectPublicKeyInfoRef};
use x509_cert::Certificate;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512, Digest};

use crate::error::MgmError;
use crate::MAIN_STRING;
use crate::util::{convert_handlers, get_file_path, get_new_object_basics, get_op_key, list_objects, print_object_properties, read_input_bytes, read_input_string, read_pem_file, select_one_object, write_bytes_to_file};

use crate::util::{delete_objects};

static ASYM_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Asymmetric keys", MAIN_STRING));

const OID_EC_PUB_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_ECBP256_PUB_KEY: &[u8] = &[0x06, 0x0A, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const OID_ECBP384_PUB_KEY: &[u8] = &[0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const OID_ECBP512_PUB_KEY: &[u8] = &[0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D];
const OID_ED25519_PUB_KEY: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

const OID_RSA_KEY: &str = "1.2.840.113549.1.1.1";
const OID_EC_KEY: &str = "1.2.840.10045.2.1";
const OID_ED25519_KEY: &str = "1.3.101.112";

const OID_ECK256_ALGORITHM: &str = "1.3.132.0.10";
const OID_ECP224_ALGORITHM: &str = "1.3.132.0.33";
const OID_ECP256_ALGORITHM: &str = "1.2.840.10045.3.1.7";
const OID_ECP384_ALGORITHM: &str = "1.3.132.0.34";
const OID_ECP521_ALGORITHM: &str = "1.3.132.0.35";
const OID_ECBP256_ALGORITHM: &str = "1.3.36.3.3.2.8.1.1.7";
const OID_ECBP384_ALGORITHM: &str = "1.3.36.3.3.2.8.1.1.11";
const OID_ECBP512_ALGORITHM: &str = "1.3.36.3.3.2.8.1.1.13";


const RSA_KEY_CAPABILITIES: [ObjectCapability; 6] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

const EC_KEY_CAPABILITIES: [ObjectCapability; 4] = [
    ObjectCapability::SignEcdsa,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

const ED_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::SignEddsa,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

const OPAQUE_CAPABILITIES: [ObjectCapability; 1] = [
    ObjectCapability::ExportableUnderWrap];

const RSA_KEY_ALGORITHM: [ObjectAlgorithm; 3] = [
    ObjectAlgorithm::Rsa2048,
    ObjectAlgorithm::Rsa3072,
    ObjectAlgorithm::Rsa4096];

const EC_KEY_ALGORITHM: [ObjectAlgorithm; 8] = [
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

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum AsymTypes {
    #[default]
    Keys,
    X509Certificates,
}

impl Display for AsymTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsymTypes::Keys => write!(f, "Private keys"),
            AsymTypes::X509Certificates => write!(f, "X509Certificates"),
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

fn get_rsa_key_algo(size_in_bytes:u32) -> Result<ObjectAlgorithm, MgmError> {
    match size_in_bytes {
        256 => Ok(ObjectAlgorithm::Rsa2048),
        384 => Ok(ObjectAlgorithm::Rsa3072),
        512 => Ok(ObjectAlgorithm::Rsa4096),
        _ => {
            Err(MgmError::Error(format!("Unsupported RSA key size {}", (size_in_bytes * 8))))
        }
    }
}

fn get_new_key_note(key_desc: &ObjectDescriptor) -> String {
    key_desc.to_string()
            .replace("Sequence:  0\t", "")
            .replace("Origin: Generated\t", "")
            .replace("\t", "\n")
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    match gen_asym_key(session, authkey) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub fn gen_asym_key(session: &Session, authkey: &ObjectDescriptor) -> Result<ObjectDescriptor, MgmError> {
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

    cliclack::note("Generating asymmetric key with:", get_new_key_note(&new_key))?;
    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating key...");
        let key = session
            .generate_asymmetric_key_with_keyid(
                new_key.id, &new_key.label, &new_key.capabilities, &new_key.domains, new_key.algorithm)?;
        spinner.stop("");
        new_key.id = key.get_key_id();
        cliclack::log::success(
            format!("Generated asymmetric keypair with ID 0x{:04x} on the device", new_key.id))?;

    }
    Ok(new_key)
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    match import_asym_key(session, authkey, get_file_path("Enter path to PEM file containing private key or X509Certificate: ")?) {
        Ok(_) => Ok(()),
        Err(e) => Err(e)
    }
}

fn oid_to_ec_algorithm(oid: &ObjectIdentifier) -> Result<ObjectAlgorithm, MgmError> {
    match oid.to_string().as_str() {
        OID_ECK256_ALGORITHM => Ok(ObjectAlgorithm::EcK256),
        OID_ECP224_ALGORITHM => Ok(ObjectAlgorithm::EcP224),
        OID_ECP256_ALGORITHM => Ok(ObjectAlgorithm::EcP256),
        OID_ECP384_ALGORITHM => Ok(ObjectAlgorithm::EcP384),
        OID_ECP521_ALGORITHM => Ok(ObjectAlgorithm::EcP521),
        OID_ECBP256_ALGORITHM => Ok(ObjectAlgorithm::EcBp256),
        OID_ECBP384_ALGORITHM => Ok(ObjectAlgorithm::EcBp384),
        OID_ECBP512_ALGORITHM => Ok(ObjectAlgorithm::EcBp512),
        _ => Err(MgmError::Error("Unsupported curve".to_string())),
    }
}

fn import_pkcs1_rsa(session: &Session, authkey: &ObjectDescriptor, der_bytes: &[u8]) -> Result<ObjectDescriptor, MgmError> {
    let rsa = rsa::RsaPrivateKey::from_pkcs1_der(der_bytes)?;
    if rsa.primes().len() != 2 {
        return Err(MgmError::InvalidInput("RSA key does not have exactly two primes".to_string()));
    }
    let p = rsa.primes()[0].to_bytes_be();
    let q = rsa.primes()[1].to_bytes_be();
    let key_algorithm = get_rsa_key_algo((rsa.n().bits() / 8) as u32)?;

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::AsymmetricKey, &RSA_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = key_algorithm;

    cliclack::note("Importing RSA key with: ", get_new_key_note(&new_key))?;
    if cliclack::confirm("Import RSA key?").interact()? {
        new_key.id = session
            .import_rsa_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                &p.to_vec(),
                &q.to_vec())?;
        cliclack::log::success(
            format!("Imported RSA keypair with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(new_key)
}

fn import_sec1_ec(session: &Session, authkey: &ObjectDescriptor, der_bytes: &[u8]) -> Result<ObjectDescriptor, MgmError> {
    let sec1 = ::sec1::EcPrivateKey::from_der(der_bytes)?;
    let s = sec1.private_key.to_vec();

    let curve_oid = match sec1.parameters {
        Some(::sec1::EcParameters::NamedCurve(oid)) => oid,
        _ => {
            return Err(MgmError::InvalidInput("EC key parameters are not a namedCurve OID (explicit or unsupported form)".to_string()));
        }
    };
    let key_algo = oid_to_ec_algorithm(&curve_oid)?;

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::AsymmetricKey, &EC_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = key_algo;

    cliclack::note("Importing EC key with: ", get_new_key_note(&new_key))?;

    if cliclack::confirm("Import EC key?").interact()? {
        new_key.id = session
            .import_ec_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                &s.to_vec())?;
        cliclack::log::success(
            format!("Imported EC keypair with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(new_key)

}


pub fn import_pkcs8_ed25519(session: &Session, authkey: &ObjectDescriptor, der_bytes: &[u8]) -> Result<ObjectDescriptor, MgmError> {
    // Parse PKCS#8 Ed25519 DER; extract 32-byte seed.
    // Accepts 32, 34 (nested) or 64 (seed+public) lengths.
    let seed:Vec<u8> = match der_bytes.len() {
        32 => {
            der_bytes.to_vec()
        },
        34 if der_bytes[0] == 0x04 && der_bytes[1] == 0x20 => {
            der_bytes[2..34].to_vec()
        },
        64 => {
            der_bytes[0..32].to_vec()
        },
        _ => {
            return Err(MgmError::InvalidInput(format!(
                "Unsupported Ed25519 private key length {} (expected 32, 34 or 64)",
                der_bytes.len()
            )));
        }
    };

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::AsymmetricKey, &ED_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = ObjectAlgorithm::Ed25519;

    cliclack::note("Importing ED25519 key with: ", get_new_key_note(&new_key))?;
    if cliclack::confirm("Import EC key?").interact()? {
        new_key.id = session
            .import_ed_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                seed.as_slice())?;
        cliclack::log::success(
            format!("Imported EC keypair with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(new_key)
}

pub fn import_asym_key(session: &Session, authkey: &ObjectDescriptor, filepath: String) -> Result<ObjectDescriptor, MgmError> {
    let pem = read_pem_file(filepath)?;
    let der_bytes = pem.contents();

    if Certificate::from_der(der_bytes).is_ok() {
        let mut new_obj = get_new_object_basics(authkey, ObjectType::Opaque, &OPAQUE_CAPABILITIES, &[])?;
        new_obj.algorithm = ObjectAlgorithm::OpaqueX509Certificate;
        cliclack::note("Importing X509Certificate with: ", get_new_key_note(&new_obj))?;
        if cliclack::confirm("Import X509Certificate?").interact()? {
            new_obj.id = session.import_cert(
                new_obj.id,
                &new_obj.label,
                &new_obj.domains,
                &new_obj.capabilities,
                der_bytes
            )?;
            cliclack::log::success(
                format!("Imported X509Certificate with ID 0x{:04x} on the device", new_obj.id)
            )?;
        }
        return Ok(new_obj)
    }

    let new_key =
        if let Ok(nk) = import_pkcs1_rsa(session, authkey, der_bytes) {
            nk
        } else if let Ok(nk) = import_sec1_ec(session, authkey, der_bytes) {
            nk
        } else if let Ok(privkey) = PrivateKeyInfo::try_from(der_bytes) {
            // Continue to PKCS#8 parsing
            let alg = privkey.algorithm;
            let oid_str = alg.oid.to_string();
            match oid_str.as_str() {
                OID_RSA_KEY => {
                    import_pkcs1_rsa(session, authkey, privkey.private_key)?
                },
                OID_EC_KEY => {
                    import_sec1_ec(session, authkey, privkey.private_key)?
                },
                OID_ED25519_KEY => {
                    import_pkcs8_ed25519(session, authkey, privkey.private_key)?
                }
                _ => {
                    return Err(MgmError::InvalidInput(format!("Unsupported private key algorithm OID: {}", oid_str)))
                },
            }
        } else {
            return Err(MgmError::InvalidInput("Failed to parse private key: unsupported format".to_string()))
        };
    Ok(new_key)
}

fn get_all_asym_objects(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.
                              list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    keys.extend(session.
                           list_objects_with_filter(0, ObjectType::Opaque, "",ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    Ok(keys)
}

fn list(session: &Session) -> Result<(), MgmError> {
    let types = cliclack::multiselect("Select type to list")
        .initial_values([AsymTypes::Keys, AsymTypes::X509Certificates].to_vec())
        .required(false)
        .item(AsymTypes::Keys, AsymTypes::Keys, "")
        .item(AsymTypes::X509Certificates, AsymTypes::X509Certificates, "")
        .interact()?;
    let mut keys = Vec::new();
    if types.contains(&AsymTypes::Keys) {
        keys.extend(session.
                               list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?);
    }
    if types.contains(&AsymTypes::X509Certificates) {
        keys.extend(session.
                               list_objects_with_filter(0, ObjectType::Opaque, "",ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    }
    list_objects(session, &keys)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_asym_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let key_handles: Vec<ObjectHandle> = get_all_asym_objects(session)?;
    delete_objects(session, key_handles)
}

fn get_public_key(session: &Session) -> Result<(), MgmError> {
    let keys = session.
                          list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    let key = select_one_object(
        "Select key" , convert_handlers(session, &keys)?)?;
    let pubkey = session.get_pubkey(key.id)?;

    let pem_pubkey: String;
    let key_algo = pubkey.1;
    if RSA_KEY_ALGORITHM.contains(&key_algo) {
        let modulus = rsa::BigUint::from_bytes_be(pubkey.0.clone().as_slice());
        let exponent = rsa::BigUint::from_bytes_be(&[0x01, 0x00, 0x01]);
        let rsa_pubkey:RsaPublicKey = RsaPublicKey::new(modulus, exponent)?;
        pem_pubkey = rsa_pubkey.to_public_key_pem(rsa::pkcs8::LineEnding::LF)?;

    } else if EC_KEY_ALGORITHM.contains(&key_algo) {
        let mut ec_pubkey_bytes_1: Vec<u8> = Vec::new();
        ec_pubkey_bytes_1.push(0x04);
        ec_pubkey_bytes_1.extend(pubkey.0.clone());

        pem_pubkey = match key_algo {
            ObjectAlgorithm::EcK256 => {
                let point = EncodedPointK256::from_bytes(&ec_pubkey_bytes_1)?;
                let key = VerifyingKeyK256::from_encoded_point(&point)?;
                key.to_public_key_pem(Default::default())?
            }
            ObjectAlgorithm::EcP224 => {
                let point = EncodedPointP224::from_bytes(&ec_pubkey_bytes_1)?;
                let key = VerifyingKeyP224::from_encoded_point(&point)?;
                key.to_public_key_pem(Default::default())?
            }
            ObjectAlgorithm::EcP256 => {
                let point = EncodedPointP256::from_bytes(&ec_pubkey_bytes_1)?;
                let key = VerifyingKeyP256::from_encoded_point(&point)?;
                key.to_public_key_pem(Default::default())?
            }
            ObjectAlgorithm::EcP384 => {
                let point = EncodedPointP384::from_bytes(&ec_pubkey_bytes_1)?;
                let key = VerifyingKeyP384::from_encoded_point(&point)?;
                key.to_public_key_pem(Default::default())?
            }
            ObjectAlgorithm::EcP521 => {
                let point = EncodedPointP521::from_bytes(&ec_pubkey_bytes_1)?;
                let key = PublicKeyP521::try_from(point)
                    .map_err(|e| MgmError::InvalidInput(format!("Failed to parse ECP521 public key: {e}")))?;
                let spki = key.to_public_key_der()?;
                spki.to_pem("PUBLIC KEY", LineEnding::LF)?
            }
            ObjectAlgorithm::EcBp256 | ObjectAlgorithm::EcBp384 | ObjectAlgorithm::EcBp512 => {
                let curve_oid: &[u8] = match key_algo {
                    ObjectAlgorithm::EcBp256 => OID_ECBP256_PUB_KEY,
                    ObjectAlgorithm::EcBp384 => OID_ECBP384_PUB_KEY,
                    ObjectAlgorithm::EcBp512 => OID_ECBP512_PUB_KEY,
                    _ => unreachable!(),
                };

                // AlgorithmIdentifier = SEQUENCE { id-ecPublicKey, brainpoolP256r1 }
                // We'll build: 30 <len> <ID_EC_PUB_KEY> <OID_BRAINPOOL_P256R1>
                let mut alg_id = Vec::new();
                alg_id.push(0x30);
                push_der_length(&mut alg_id, OID_EC_PUB_KEY.len() + curve_oid.len());
                alg_id.extend_from_slice(OID_EC_PUB_KEY);
                alg_id.extend_from_slice(curve_oid);

                get_spki_pem_string(ec_pubkey_bytes_1.as_slice(), alg_id)
            }
            _ => {"Unsupported curve".to_string()}
        };

    } else if key_algo == ObjectAlgorithm::Ed25519 {
        let mut algo_seq = Vec::new();
        algo_seq.push(0x30);
        push_der_length(&mut algo_seq, OID_ED25519_PUB_KEY.len());
        algo_seq.extend_from_slice(OID_ED25519_PUB_KEY);
        pem_pubkey = get_spki_pem_string(pubkey.0.as_slice(), algo_seq);

    } else {
        cliclack::log::error(format!("Object 0x{:04x} is not an asymmetric key", key.id))?;
        return Ok(())
    }

    println!("{}\n", pem_pubkey);

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.pubkey.pem", key.id);
        if let Err(err) = write_bytes_to_file(pem_pubkey.into_bytes(), "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write public key 0x{:04x} to file. {}", key.id, err))?;
        }
    }
    Ok(())
}

fn get_spki_pem_string(pubkey_raw: &[u8], algorithm_seq: Vec<u8>) -> String {
    let mut bit_string = Vec::new();
    {
        bit_string.push(0x03);
        push_der_length(&mut bit_string, 1 + pubkey_raw.len());
        bit_string.push(0x00); // unused bits
        bit_string.extend_from_slice(pubkey_raw);
    }

    // Outer SEQUENCE
    let mut spki = Vec::new();
    {
        spki.push(0x30);
        push_der_length(&mut spki, algorithm_seq.len() + bit_string.len());
        spki.extend_from_slice(&algorithm_seq);
        spki.extend_from_slice(&bit_string);
    }

    get_pem_string(spki.as_slice(), "PUBLIC KEY")
}

/// Encode DER length (definite, short or long form)
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push(((len >> 8) & 0xFF) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

fn get_pem_string(cert_bytes: &[u8], label: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(cert_bytes);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(format!("-----END {}-----\n", label).as_str());
    pem
}


fn get_cert(session: &Session) -> Result<(), MgmError> {
    let certs = session.list_objects_with_filter(0, ObjectType::Opaque, "", ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?;
    let cert = select_one_object(
        "Select certificates", convert_handlers(session, &certs)?)?;

    let cert_bytes = session.get_opaque(cert.id)?;
    let pem = get_pem_string(cert_bytes.as_slice(), "CERTIFICATE");

    println!("{}\n", pem);

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.cert.pem", cert.id);
        if let Err(err) = write_bytes_to_file(pem.into_bytes(), "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write certificate 0x{:04x} to file. {}", cert.id, err))?;
        }
    }
    Ok(())
}

fn get_hashed_bytes(algo: &ObjectAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
    match algo {
        ObjectAlgorithm::RsaPkcs1Sha1 |
        ObjectAlgorithm::RsaPssSha1 |
        ObjectAlgorithm::EcdsaSha1 |
        ObjectAlgorithm::RsaOaepSha1 => {
            let mut h = Sha1::new();
            h.update(input);
            Ok(h.finalize().to_vec())
        },
        ObjectAlgorithm::RsaPkcs1Sha256 |
        ObjectAlgorithm::RsaPssSha256 |
        ObjectAlgorithm::EcdsaSha256 |
        ObjectAlgorithm::RsaOaepSha256 => {
            let mut h = Sha256::new();
            h.update(input);
            Ok(h.finalize().to_vec())
        },
        ObjectAlgorithm::RsaPkcs1Sha384 |
        ObjectAlgorithm::RsaPssSha384 |
        ObjectAlgorithm::EcdsaSha384 |
        ObjectAlgorithm::RsaOaepSha384 => {
            let mut h = Sha384::new();
            h.update(input);
            Ok(h.finalize().to_vec())
        },
        ObjectAlgorithm::RsaPkcs1Sha512 |
        ObjectAlgorithm::RsaPssSha512 |
        ObjectAlgorithm::EcdsaSha512 |
        ObjectAlgorithm::RsaOaepSha512 => {
            let mut h = Sha512::new();
            h.update(input);
            Ok(h.finalize().to_vec())
        },
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

    let key = get_op_key(
        session, authkey,
        [ObjectCapability::SignPkcs, ObjectCapability::SignPss, ObjectCapability::SignEcdsa, ObjectCapability::SignEddsa].to_vec().as_ref(),
        ObjectType::AsymmetricKey,
        &[])?;

    let sig;
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
        let algorithm = algorithm.interact()?;

        let hashed_bytes = get_hashed_bytes(&algorithm, input.as_bytes())?;
        if [ObjectAlgorithm::RsaPkcs1Sha1, ObjectAlgorithm::RsaPkcs1Sha256,
            ObjectAlgorithm::RsaPkcs1Sha384, ObjectAlgorithm::RsaPkcs1Sha512].contains(&algorithm) {
            sig = session.sign_pkcs1v1_5(key.id, true, hashed_bytes.as_slice())?;
        } else {
            let mgf1_algo = get_mgf1_algorithm(&algorithm)?;
            sig = session.sign_pss(key.id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?;
        }
        cliclack::log::success(format!("Signed data using {} and key 0x{:04x}", algorithm, key.id))?;

    } else if EC_KEY_ALGORITHM.contains(&key.algorithm) {
        if key.capabilities.contains(&ObjectCapability::SignEcdsa) &&
            authkey.capabilities.contains(&ObjectCapability::SignEcdsa) {
            let algorithm = cliclack::select("Select ECDSA signing algorithm")
                .item(ObjectAlgorithm::EcdsaSha1, "ECDSA with SHA1", "")
                .item(ObjectAlgorithm::EcdsaSha256, "ECDSA with SHA256", "")
                .item(ObjectAlgorithm::EcdsaSha384, "ECDSA with SHA384", "")
                .item(ObjectAlgorithm::EcdsaSha512, "ECDSA with SHA512", "")
                .interact()?;
            let hashed_bytes = get_hashed_bytes(&algorithm, input.as_bytes())?;
            sig = session.sign_ecdsa(key.id, hashed_bytes.as_slice())?;
            cliclack::log::success(format!("Signed data using {} and key 0x{:04x}", algorithm, key.id))?;
        } else {
            return Err(MgmError::Error("Selected key has no ECDSA signing capabilities".to_string()))
        }
    } else if key.algorithm == ObjectAlgorithm::Ed25519 {
        if key.capabilities.contains(&ObjectCapability::SignEddsa) &&
            authkey.capabilities.contains(&ObjectCapability::SignEddsa) {
            sig = session.sign_eddsa(key.id, input.as_bytes())?;
            cliclack::log::success(format!("Signed data using EDDSA and key 0x{:04x}", key.id))?;
        } else {
            return Err(MgmError::Error("Selected key has no EDDSA signin capabilities".to_string()))
        }
    } else {
        return Err(MgmError::Error("Selected key has no asymmetric signing capabilities".to_string()))
    };

    cliclack::log::success(format!("Signature in HEX:\n{}", hex::encode(&sig)))?;

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

    let key = get_op_key(
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

    let data = if algorithm == ObjectAlgorithm::RsaPkcs1Decrypt {
        session.decrypt_pkcs1v1_5(key.id, enc.as_slice())?
    } else {
        let label: String = cliclack::input("Enter OAEP label in HEX format (Default is empty): ")
            .default_input("")
            .validate(|input: &String| {
                if hex::decode(input).is_err() {
                    Err("Input must be in hex format")
                } else {
                    Ok(())
                }
            }).interact()?;
        let label = if label.is_empty() {Vec::new()} else {hex::decode(label)?};
        let label = get_hashed_bytes(&algorithm, label.as_slice())?;
        let mgf1_algo = get_mgf1_algorithm(&algorithm)?;
        session.decrypt_oaep(key.id, enc.as_slice(), label.as_slice(), mgf1_algo)?
    };
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
    let hsm_key = get_op_key(
        session, authkey,
        [ObjectCapability::DeriveEcdh].to_vec().as_ref(),
        ObjectType::AsymmetricKey,
        &EC_KEY_ALGORITHM)?;

    let peer_key = read_pem_file(get_file_path("Enter path to PEM file containing peer public key in PEM format:")?)?;
    let peer_key = SubjectPublicKeyInfoRef::from_der(peer_key.contents())?;
    let peer_key = peer_key.subject_public_key.raw_bytes();

    cliclack::log::success(hex::encode(session.derive_ecdh(hsm_key.id, peer_key)?))?;

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
    let keys = convert_handlers(session, &keys)?;

    let mut attested_keys = keys.clone();
    attested_keys.retain(|k| k.origin == ObjectOrigin::Generated);
    let attested_key = select_one_object("Select key to attest", attested_keys)?;

    let mut attesting_keys = keys.clone();
    attesting_keys.retain(|k| k.capabilities.contains(&ObjectCapability::SignAttestationCertificate));
    let mut device_key = ObjectDescriptor::new();
    device_key.label = "Device attestation key".to_string();
    attesting_keys.push(device_key);
    let attesting_key = select_one_object("Select attesting key", attesting_keys)?;

    let cert_bytes = get_attestation_cert(session, authkey, attested_key.id, attesting_key.id)?;
    let cert_pem = get_pem_string(cert_bytes.as_slice(), "CERTIFICATE");
    println!("{}\n", cert_pem.clone());

    if cliclack::confirm("Write to file?").interact()? {
        if let Err(err) = write_bytes_to_file(cert_pem.into_bytes(), "", "attestation_cert.pem") {
            cliclack::log::error(
                format!("Failed to write attestation certificate to file. {}", err))?;
        }
    }
    Ok(())
}

pub fn get_attestation_cert(session: &Session, authkey: &ObjectDescriptor, attested_key: u16, attesting_key: u16) -> Result<Vec<u8>, MgmError> {
    if attesting_key == 0 {
        Ok(session.sign_attestation_certificate(attested_key, attesting_key)?)
    } else {
        let delete_template_cert = import_template_cert(session, authkey, attesting_key)?;
        let cert = session.sign_attestation_certificate(attested_key, attesting_key)?;
        if delete_template_cert {
            session.delete_object(attesting_key, ObjectType::Opaque)?;
        }
        Ok(cert)
    }
}

fn import_template_cert(session:&Session, authkey:&ObjectDescriptor, key_id:u16) -> Result<bool, MgmError> {
    let mut delete_template_cert = false;
    match session.get_object_info(key_id, ObjectType::Opaque) {
        Ok(template_cert) => {
            if template_cert.algorithm != ObjectAlgorithm::OpaqueX509Certificate {
                return Err(MgmError::Error("There is already an opaque object with the same ID as the attesting key. \
                This slot needs to be empty or occupied by an X509Certificate object for the attestation operation to succeed".to_string()));
            }
        },
        Err(_) => {
            match session.sign_attestation_certificate(key_id, 0) {
                Ok(template_cert) => {
                    session.import_cert(key_id, "template_cert", &authkey.domains, &Vec::new(), template_cert.as_slice())?;
                },
                Err(_) => {
                    cliclack::log::error("Cannot find a certificate template.".to_string())?;
                    let file_path = get_file_path("Enter path to PEM file containing an X509Certificate \
                    to use as a template for the attestation certificate or press ESC to cancel this operation. \
                    The template certificate will be deleted after successful execution")?;

                    let pem = read_pem_file(file_path)?;
                    let cert_bytes = pem.contents();
                    // let cert = openssl::x509::X509::from_der(cert_bytes)?;
                    match Certificate::from_der(cert_bytes) {
                        Ok(_) => {
                            session.import_cert(key_id, "template_cert", &authkey.domains, &Vec::new(), cert_bytes)?;
                        },
                        Err(e) => {
                            return Err(MgmError::InvalidInput(format!("Failed to parse X509Certificate from DER: {e}")));
                        }
                    }
                }
            }
            delete_template_cert = true;
        },
    }
    Ok(delete_template_cert)
}