use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::sync::LazyLock;
use openssl::pkey;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::{MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectOrigin, ObjectType};
use yubihsmrs::Session;

use error::MgmError;
use MAIN_STRING;
use util::{convert_handlers, get_ec_pubkey_from_pem_string, get_file_path, get_new_object_basics, get_op_key, list_objects, print_object_properties, read_input_bytes, read_input_string, read_pem_file, read_string_from_file, select_one_object, write_bytes_to_file};

use crate::util::{delete_objects};

static ASYM_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Asymmetric keys", MAIN_STRING));

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

fn get_algo_from_nid(nid: Nid) -> Result<ObjectAlgorithm, MgmError> {
    match nid {
        Nid::X9_62_PRIME256V1 => Ok(ObjectAlgorithm::EcP256),
        Nid::SECP256K1 => Ok(ObjectAlgorithm::EcK256),
        Nid::SECP384R1 => Ok(ObjectAlgorithm::EcP384),
        Nid::SECP521R1 => Ok(ObjectAlgorithm::EcP521),
        Nid::SECP224R1 => Ok(ObjectAlgorithm::EcP224),
        Nid::BRAINPOOL_P256R1 => Ok(ObjectAlgorithm::EcBp256),
        Nid::BRAINPOOL_P384R1 => Ok(ObjectAlgorithm::EcBp384),
        Nid::BRAINPOOL_P512R1 => Ok(ObjectAlgorithm::EcBp512),
        _ => {
            Err(MgmError::InvalidInput(format!("Unsupported EC curve {:?}", nid)))
        }
    }
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

pub fn import_asym_key(session: &Session, authkey: &ObjectDescriptor, filepath: String) -> Result<ObjectDescriptor, MgmError> {
    let pem = read_pem_file(filepath)?;
    let key_bytes = pem.contents();
    let mut new_key = ObjectDescriptor::new();
    match openssl::pkey::PKey::private_key_from_der(key_bytes) {
        Ok(key) => {
            match key.id() {
                pkey::Id::RSA => {
                    cliclack::log::info("Found RSA private key")?;
                    let private_rsa = key.rsa()?;

                    let Some(p) = private_rsa.p() else {
                        cliclack::log::error("Failed to read p value".to_string())?;
                        return Err(MgmError::InvalidInput("Failed to read p value".to_string()));
                    };
                    let Some(q) = private_rsa.q() else {
                        cliclack::log::error("Failed to read q value".to_string())?;
                        return Err(MgmError::InvalidInput("Failed to read q value".to_string()));
                    };

                    let key_algorithm = get_rsa_key_algo(private_rsa.size())?;
                    new_key = get_new_object_basics(
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
                    return Ok(new_key)

                }
                pkey::Id::EC => {
                    cliclack::log::info("Found EC private key")?;
                    let private_ec = key.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let Some(nid) = group.curve_name() else {
                        cliclack::log::error("Failed to read EC curve name".to_string())?;
                        return Err(MgmError::InvalidInput("Failed to read EC curve name".to_string()))
                    };

                    let key_algorithm = get_algo_from_nid(nid)?;
                    new_key = get_new_object_basics(
                        authkey, ObjectType::AsymmetricKey, &EC_KEY_CAPABILITIES, &[])?;
                    new_key.algorithm = key_algorithm;

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
                }
                pkey::Id::ED25519 => {
                    cliclack::log::info("Found ED private key")?;
                    let private_ed = PKey::private_key_from_raw_bytes(key_bytes, pkey::Id::ED25519)?;
                    let k = private_ed.raw_private_key()?;

                    new_key = get_new_object_basics(
                        authkey, ObjectType::AsymmetricKey, &ED_KEY_CAPABILITIES, &[])?;
                    new_key.algorithm = ObjectAlgorithm::Ed25519;

                    cliclack::note("Importing ED key with: ", get_new_key_note(&new_key))?;

                    if cliclack::confirm("Import ED key?").interact()? {
                        new_key.id = session
                            .import_ed_key(
                                new_key.id,
                                &new_key.label,
                                &new_key.domains,
                                &new_key.capabilities,
                                &k.to_vec())?;
                        cliclack::log::success(
                            format!("Imported ED keypair with ID 0x{:04x} on the device", new_key.id))?;
                    }
                }
                _ => cliclack::log::error("Unknown or unsupported key type")?,
            }
        }
        Err(err) => {
            let key_err = err;
            match openssl::x509::X509::from_der(key_bytes) {
                Ok(cert) => {
                    cliclack::log::info("Found X509Certificate")?;

                    new_key = get_new_object_basics(
                        authkey, ObjectType::Opaque, &OPAQUE_CAPABILITIES, &[])?;
                    new_key.algorithm = ObjectAlgorithm::OpaqueX509Certificate;

                    cliclack::note("Importing X509Certificate with: ", get_new_key_note(&new_key))?;
                    if cliclack::confirm("Import X509Certificate?").interact()? {
                        new_key.id = session
                            .import_cert(
                                new_key.id,
                                &new_key.label,
                                &new_key.domains,
                                &new_key.capabilities,
                                &cert.to_pem()?)?;
                        cliclack::log::success(format!("Imported X509Certificate with ID 0x{:04x} on the device", new_key.id))?;
                    }
                }
                Err(cert_err) => {
                    cliclack::log::error("Failed to find either private key or X509Certificate".to_string())?;
                    cliclack::log::error(format!("{}", key_err))?;
                    cliclack::log::error(format!("{}", cert_err))?;
                }
            }
        }
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

    let pubkey = match session.get_pubkey(key.id) {
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
    let certs = session.list_objects_with_filter(0, ObjectType::Opaque, "", ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?;
    let cert = select_one_object(
        "Select certificates", convert_handlers(session, &certs)?)?;


    let cert_bytes = session.get_opaque(cert.id)?;
    let cert_pem = openssl::x509::X509::from_der(cert_bytes.as_slice())?.to_pem()?;
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

fn get_hashed_bytes(algo: &ObjectAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
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

    let peer_key = read_string_from_file("Enter path to PEM file containing the peer public key: ")?;
    let (peer_key, nid) = get_ec_pubkey_from_pem_string(peer_key)?;
    let peer_key_algo = get_algo_from_nid(nid)?;

    if hsm_key.algorithm != peer_key_algo {
        return Err(MgmError::Error("Peer EC public key has a different algorithm from the YubiHSM key".to_string()));
    }
    cliclack::log::success(hex::encode(session.derive_ecdh(hsm_key.id, peer_key.as_slice())?))?;

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
    let cert_pem = openssl::x509::X509::from_der(cert_bytes.as_slice())?.to_pem()?;
    if let Ok(str) = String::from_utf8(cert_pem.clone()) { println!("{}\n", str) }

    if cliclack::confirm("Write to file?").interact()? {
        if let Err(err) = write_bytes_to_file(cert_pem, "", "attestation_cert.pem") {
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
                    let cert = openssl::x509::X509::from_der(cert_bytes)?;
                    session.import_cert(key_id, "template_cert", &authkey.domains, &Vec::new(), &cert.to_pem()?)?;
                }
            }
            delete_template_cert = true;
        },
    }
    Ok(delete_template_cert)
}