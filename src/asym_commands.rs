use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display};

use openssl::{base64, pkey};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;

use error::MgmError;
use util::{BasicDescriptor, get_domains, get_id, get_intesected_capabilities, get_label, get_object_properties_str, get_permissible_capabilities, list_objects, print_object_properties, read_file_bytes, read_file_string, select_multiple_objects, select_object_capabilities, select_one_object, write_file};

use crate::util::{delete_objects};


const ATTESTATION_CERT_TEMPLATE: &str =
    "MIIC+jCCAeKgAwIBAgIGAWbt9mc3MA0GCSqGSIb3DQEBBQUAMD4xPDA6BgNVBAMM\
     M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
     dGlvbjAeFw0xODExMDcxMTM3MjBaFw00ODEwMzExMTM3MjBaMD4xPDA6BgNVBAMM\
     M0R1bW15IGNlcnRpZmljYXRlIGNyZWF0ZWQgYnkgYSBDRVNlQ29yZSBhcHBsaWNh\
     dGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTxMBMtwHJCzNHi\
     d0GszdXM49jQdEZOuaLK1hyIjpuhRImJYbdvmF5cYa2suR2yw6DygWGFLafqVEuL\
     dXvnib3r0jBX2w7ZSrPWuJ592QUgNllHCvNG/dNgwLfCVOr9fs1ifJaa09gtQ2EG\
     3iV7j3AMxb7rc8x4d3nsJad+UPCyqB3HXGDRLbOT38zI72zhXm4BqiCMt6+2rcPE\
     +nneNiTMVjrGwzbZkCak6xnwq8/tLTtvD0+yPLQdKb4NaQfXPmYNTrzTmvYmVD8P\
     0bIUo/CoXIh0BkJXwHzX7J9nDW9Qd7BR2Q2vbUaou/STlWQooqoTnVnEK8zvAXkl\
     ubqSUPMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAGXwmRWewOcbPV/Jx6wkNDOvE\
     oo4bieBqeRyU/XfDYbuevfNSBnbQktThl1pR21hrJ2l9qV3D1AJDKck/x74hyjl9\
     mh37eqbPAdfx3yY7vN03RYWr12fW0kLJA9bsm0jYdJN4BHV/zCXlSqPS0The+Zfg\
     eVCiQCnEZx/z1jfxwIIg6N8Y7luPWIi36XsGqI75IhkJFw8Jup5HIB4p4P0txinm\
     hxzAwAjKm7yCiBA5oxX1fvSPdlwMb9mcO7qC5wKrsMyuzIpllBbGaCRFCcAtu9Zu\
     MvBJNrMLPK3bz4QvT5dYW/cXcjJbnIDqQKqSVV6feYk3iyS07HkaPGP3rxGpdQ==";

const RSA_KEY_CAPABILITIES: [ObjectCapability; 5] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::ExportableUnderWrap];

const EC_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::SignEcdsa,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::ExportableUnderWrap];

const ED_KEY_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::SignEddsa,
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
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
    GetPublicKey,
    DeleteKey,
    PerformSignature,
    PerformRsaDecryption,
    DeriveEcdh,
    SignAttestationCert,
    ManageJavaKeys,
    ReturnToMainMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AsymJavaCommand {
    #[default]
    ListKeys,
    GenerateKey,
    ImportKey,
    DeleteKey,
    ReturnToMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AsymKeyTypes {
    #[default]
    RSA,
    EC,
    ED,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum HashAlgorithm {
    #[default]
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HashAlgorithm::SHA1 => write!(f, "SHA1"),
            HashAlgorithm::SHA256 => write!(f, "SHA256"),
            HashAlgorithm::SHA384 => write!(f, "SHA384"),
            HashAlgorithm::SHA512 => write!(f, "SHA512"),

        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum InputOutputFormat {
    #[default]
    STDIN,
    BINARY,
    PEM,
}

impl Display for InputOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputOutputFormat::STDIN => write!(f, "Stdin"),
            InputOutputFormat::BINARY => write!(f, "Binary file"),
            InputOutputFormat::PEM => write!(f, "PEM file"),
        }
    }
}

pub fn exec_asym_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_asym_command(session, current_authkey)?;
        let res = match cmd {
            AsymCommand::ListKeys => asym_list_keys(session),
            AsymCommand::GetKeyProperties => asym_get_key_properties(session),
            AsymCommand::GenerateKey => asym_gen_key(session, current_authkey),
            AsymCommand::ImportKey => asym_import_key(session, current_authkey),
            AsymCommand::DeleteKey => asym_delete_key(session),
            AsymCommand::GetPublicKey => asym_get_public_key(session),
            AsymCommand::PerformSignature => asym_sign(session, current_authkey),
            AsymCommand::PerformRsaDecryption => asym_decrypt(session, current_authkey),
            AsymCommand::DeriveEcdh => asym_derive_ecdh(session, current_authkey),
            AsymCommand::SignAttestationCert => Err(MgmError::Error("Not implemented yet".to_string())),
            AsymCommand::ManageJavaKeys => asym_java_manage(session, current_authkey),
            AsymCommand::ReturnToMainMenu => return Ok(()),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn get_asym_command(session: &Session, current_authkey: u16) -> Result<AsymCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands = cliclack::select("").initial_value(AsymCommand::ListKeys);
    commands = commands.item(AsymCommand::ListKeys, "List keys", "");
    commands = commands.item(AsymCommand::GetKeyProperties, "Get key properties", "");
    if capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) {
        commands = commands.item(AsymCommand::GenerateKey, "Generate key", "");
    }
    if capabilities.contains(&ObjectCapability::PutAsymmetricKey) {
        commands = commands.item(AsymCommand::ImportKey, "Import key or certificate", "");
    }
    if capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) ||
        capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands = commands.item(AsymCommand::DeleteKey, "Delete key or certificate", "");
    }
    commands = commands.item(AsymCommand::GetPublicKey, "Get public key", "");
    if HashSet::from([ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa]).intersection(&capabilities).count() > 0 {
        commands = commands.item(AsymCommand::PerformSignature, "Perform signature", "");
    }
    if HashSet::from([
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep]).intersection(&capabilities).count() > 0 {
        commands = commands.item(AsymCommand::PerformRsaDecryption, "Perform RSA decryption", "");
    }
    if capabilities.contains(&ObjectCapability::DeriveEcdh) {
        commands = commands.item(AsymCommand::DeriveEcdh, "Derive ECDH", "");
    }
    if capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(AsymCommand::SignAttestationCert, "Sign attestation certificate", "Not implemented yet");
    }
    if HashSet::from([
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::PutAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey]).intersection(&capabilities).count() > 0
        &&
        HashSet::from([
            ObjectCapability::PutOpaque,
            ObjectCapability::DeleteOpaque]).intersection(&capabilities).count() > 0 {
        commands = commands.item(AsymCommand::ManageJavaKeys, "Manage JAVA keys",
                      "Usable with SunPKCS11 provider. A JAVA key is a pair of an asymmetric key and an \
                      X509Certificate, both stored on the YubiHSM using the same ObjectID");
    }
    commands = commands.item(AsymCommand::ReturnToMainMenu, "Return to main menu", "");
    Ok(commands.interact()?)
}

fn get_hash_algorithm() -> Result<HashAlgorithm, MgmError> {
    Ok(cliclack::select("Select hash algorithm:")
        .item(HashAlgorithm::SHA1, "SHA1", "")
        .item(HashAlgorithm::SHA256, "SHA256", "")
        .item(HashAlgorithm::SHA384, "SHA384", "")
        .item(HashAlgorithm::SHA512, "SHA512", "")
        .interact()?)
}

fn get_format(supported_formats: &Vec<InputOutputFormat>) -> Result<InputOutputFormat, MgmError> {
    let mut format = cliclack::select("Select input_format:");
    for f in supported_formats {
        format = format.item(f.clone(), f, "");
    }
    Ok(format.interact()?)
}

fn get_ec_algo() -> Result<ObjectAlgorithm, MgmError> {
    Ok(cliclack::select("Choose EC Curve:")
        .item(ObjectAlgorithm::EcP224, "secp224r1".to_string(), "")
        .item(ObjectAlgorithm::EcP256, "secp256r1".to_string(), "")
        .item(ObjectAlgorithm::EcP384, "secp384r1".to_string(), "")
        .item(ObjectAlgorithm::EcP521, "secp521r1".to_string(), "")
        .item(ObjectAlgorithm::EcK256, "secp256k1".to_string(), "")
        .item(ObjectAlgorithm::EcBp256, "brainpool256r1".to_string(), "")
        .item(ObjectAlgorithm::EcBp384, "brainpool384r1".to_string(), "")
        .item(ObjectAlgorithm::EcBp512, "brainpool512r1".to_string(), "")
        .interact()?)
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

fn get_rsa_keylen() -> Result<u32, MgmError> {
    Ok(cliclack::select("Enter key length:")
        .item(2048, "2048", "")
        .item(3072, "3072", "")
        .item(4096, "4096", "")
        .interact()?)
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

fn asym_gen_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;

    let key_algorithm: ObjectAlgorithm;
    let capabilities: Vec<ObjectCapability>;

    let key_type = cliclack::select("Choose key type:")
        .item(AsymKeyTypes::RSA, "RSA", "")
        .item(AsymKeyTypes::EC, "EC", "")
        .item(AsymKeyTypes::ED, "ED", "")
        .interact()?;

    match key_type {
        AsymKeyTypes::RSA => {
            let key_len = get_rsa_keylen()?;
            key_algorithm = get_rsa_key_algo(key_len/8)?;
            capabilities = select_object_capabilities(
                "Select key capabilities",
                false,
                true,
                &RSA_KEY_CAPABILITIES.to_vec(),
                &permissible_capabilities)?;
        }
        AsymKeyTypes::EC => {
            key_algorithm = get_ec_algo()?;
            capabilities = select_object_capabilities(
                "Select key capabilities",
                false,
                true,
                &EC_KEY_CAPABILITIES.to_vec(),
                &permissible_capabilities)?;
        }
        AsymKeyTypes::ED => {
            key_algorithm = ObjectAlgorithm::Ed25519;
            capabilities = select_object_capabilities(
                "Select key capabilities",
                false,
                true,
                &ED_KEY_CAPABILITIES.to_vec(),
                &permissible_capabilities)?;
        }
    }

    cliclack::note("Generating asymmetric key with:",
                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

    if cliclack::confirm("Generate key?").interact()? {
        let key = session
            .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)?;
        cliclack::log::success(
            format!("Generated asymmetric keypair with ID 0x{:04x} on the device", key.get_key_id()))?;
    }
    Ok(())
}

fn read_pem_file(prompt:&str) -> Result<pem::Pem, MgmError> {
    let content = read_file_string(prompt)?;
    match pem::parse(content) {
        Ok(pem) => Ok(pem),
        Err(err) => {
            cliclack::log::error("Failed to parse file content as PEM")?;
            if cliclack::confirm("Try again?").interact()? {
                read_pem_file(prompt)
            } else {
                Err(MgmError::PemError(err))
            }
        }
    }
}

fn asym_import_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let mut key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let pem = read_pem_file("Enter path to PEM file: ")?;
    let key_bytes = pem.contents();

    let permissible_capabilities = get_permissible_capabilities(session, current_authkey)?;

    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            match key.id() {
                pkey::Id::RSA => {
                    cliclack::log::info("Found RSA private key")?;
                    let private_rsa = key.rsa()?;

                    let Some(p) = private_rsa.p() else {
                        cliclack::log::error("Failed to read p value".to_string())?;
                        return Ok(())
                    };
                    let Some(q) = private_rsa.q() else {
                        cliclack::log::error("Failed to read q value".to_string())?;
                        return Ok(())
                    };

                    let key_algorithm = get_rsa_key_algo(private_rsa.size())?;

                    let capabilities = select_object_capabilities(
                        "Select key capabilities",
                        false,
                        true,
                        &RSA_KEY_CAPABILITIES.to_vec(),
                        &permissible_capabilities)?;

                    cliclack::note("Importing RSA key with: ",
                                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

                    if cliclack::confirm("Import RSA key?").interact()? {
                        key_id = session
                            .import_rsa_key(key_id, &label, &*domains, &capabilities, key_algorithm, &p.to_vec(), &q.to_vec())?;
                        cliclack::log::success(
                            format!("Imported RSA keypair with ID 0x{:04x} on the device", key_id))?;
                    }

                }
                pkey::Id::EC => {
                    cliclack::log::info("Found EC private key")?;
                    let private_ec = key.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let Some(nid) = group.curve_name() else {
                        cliclack::log::error("Failed to read EC curve name".to_string())?;
                        return Ok(())
                    };

                    let key_algorithm = get_algo_from_nid(nid)?;

                    let capabilities = select_object_capabilities(
                        "Select key capabilities",
                        false,
                        true,
                        &EC_KEY_CAPABILITIES.to_vec(),
                        &permissible_capabilities)?;

                    cliclack::note("Importing EC key with: ",
                                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

                    if cliclack::confirm("Import EC key?").interact()? {
                        key_id= session
                            .import_ec_key(key_id, &label, &*domains, &capabilities, key_algorithm, &s.to_vec())?;
                        cliclack::log::success(
                            format!("Imported EC keypair with ID 0x{:04x} on the device", key_id))?;
                    }
                }
                pkey::Id::ED25519 => {
                    cliclack::log::info("Found ED private key")?;
                    let private_ed = PKey::private_key_from_raw_bytes(key_bytes, pkey::Id::ED25519)?;
                    let k = private_ed.raw_private_key()?;

                    let capabilities = select_object_capabilities(
                        "Select key capabilities",
                        false,
                        true,
                        &ED_KEY_CAPABILITIES.to_vec(),
                        &permissible_capabilities)?;

                    cliclack::note("Importing ED key with: ",
                                   get_object_properties_str(&ObjectAlgorithm::Ed25519, &label, key_id, &domains, &capabilities))?;

                    if cliclack::confirm("Import ED key?").interact()? {
                        key_id = session
                            .import_ed_key(key_id, &label, &*domains, &capabilities, &k.to_vec())?;
                        cliclack::log::success(
                            format!("Imported ED keypair with ID 0x{:04x} on the device", key_id))?;
                    }
                }
                _ => cliclack::log::error("Unknown or unsupported key type")?,
            }
        }
        Err(err) => {
            let key_err = err;
            cliclack::log::info("Not a key. Trying to import as X509 certificate")?;
            match openssl::x509::X509::from_der(key_bytes) {
                Ok(cert) => {
                    let capabilities = select_object_capabilities(
                        "Select certificate capabilities",
                        false,
                        true,
                        &[ObjectCapability::ExportableUnderWrap].to_vec(),
                        &permissible_capabilities)?;

                    cliclack::note("Importing X509Certificate with: ",
                                   get_object_properties_str(&ObjectAlgorithm::OpaqueX509Certificate, &label, key_id, &domains, &Vec::new()))?;
                    if cliclack::confirm("Import X509Certificate?").interact()? {
                        key_id = session
                            .import_cert(key_id, &label, &*domains, &capabilities, &cert.to_pem()?)?;
                        cliclack::log::success(format!("Imported X509Certificate with ID 0x{:04x} on the device", key_id))?;
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
    Ok(())
}

fn get_all_asym_objects(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.
        list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    keys.extend(session.
        list_objects_with_filter(0, ObjectType::Opaque, "",ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    Ok(keys)
}

fn asym_list_keys(session: &Session) -> Result<(), MgmError> {
    let keys = get_all_asym_objects(session)?;
    list_objects(session, &keys)
}

fn asym_get_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_asym_objects(session)?)
}

fn asym_delete_key(session: &Session) -> Result<(), MgmError> {
    let key_handles: Vec<ObjectHandle> = get_all_asym_objects(session)?;
    delete_objects(session, key_handles)
}
/*
fn print_pem_string(pem_bytes: Vec<u8>) {
    let pem_str = String::from_utf8(pem_bytes).unwrap();
    let chars: Vec<char> = pem_str.chars().collect();
    for c in chars {
        if c == '\n' {
            println!();
        } else {
            print!("{c}");
        }
    }
}
*/
fn asym_get_public_key(session: &Session) -> Result<(), MgmError> {
    let keys = session.
        list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    let keys = select_multiple_objects(
        session, keys, "Select keys", false)?;

    if keys.is_empty() {
        cliclack::log::info("No keys were selected")?;
        return Ok(());
    }

    for key in keys {
        let pubkey = match session.get_pubkey(key.id) {
            Ok(pk) => pk,
            Err(e) => {
                cliclack::log::error(format!("Failed to get public key for asymmetric key 0x{:04x}. {}",
                                             key.id, e))?;
                continue;
            }
        };

        let filename = format!("0x{:04x}.pubkey.pem", key.id).to_string();
        let pem_pubkey;
        let key_algo = pubkey.1;
        if RSA_KEY_ALGORITHM.contains(&key_algo) {
            let e = match BigNum::from_slice(&[0x01, 0x00, 0x01]) {
                Ok(bn) => bn,
                Err(err) => {
                    cliclack::log::error(format!("Failed to construct exponent for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            let n = match BigNum::from_slice(pubkey.0.as_slice()) {
                Ok(bn) => bn,
                Err(err) => {
                    cliclack::log::error(format!("Failed to construct n for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            let rsa_pubkey = match openssl::rsa::Rsa::from_public_components(n, e) {
                Ok(rsa) => rsa,
                Err (err) => {
                    cliclack::log::error(format!("Failed to parse RSA public key for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            pem_pubkey = match rsa_pubkey.public_key_to_pem() {
                Ok(pem) => pem,
                Err(err) => {
                    cliclack::log::error(format!("Failed to convert RSA public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                    continue;
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
                    continue;
                }
            };

            let mut ctx = match BigNumContext::new() {
                Ok(bnc) => bnc,
                Err(err) => {
                    cliclack::log::error(format!("Failed to create BigNumContext for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            let mut ec_pubkey_bytes: Vec<u8> = Vec::new();
            ec_pubkey_bytes.push(0x04);
            ec_pubkey_bytes.extend(pubkey.0);
            let ec_point = match EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx) {
                Ok(p) => p,
                Err(err) => {
                    cliclack::log::error(format!("Failed to parse EC point for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            let ec_pubkey = match EcKey::from_public_key(&ec_group, &ec_point) {
                Ok(pk) => pk,
                Err(err) => {
                    cliclack::log::error(format!("Failed to parse EC public key for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            pem_pubkey = match ec_pubkey.public_key_to_pem() {
                Ok(pem) => pem,
                Err(err) => {
                    cliclack::log::error(format!("Failed to convert EC public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

        } else if key_algo == ObjectAlgorithm::Ed25519 {
            let ed_pubkey = match PKey::public_key_from_raw_bytes(pubkey.0.as_slice(), pkey::Id::ED25519) {
                Ok(pk) => pk,
                Err(err) => {
                    cliclack::log::error(format!("Failed to parse ED public key for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };

            pem_pubkey = match ed_pubkey.public_key_to_pem() {
                Ok(pem) => pem,
                Err(err) => {
                    cliclack::log::error(format!("Failed to convert ED public key to PEM format for key 0x{:04x}. {}", key.id, err))?;
                    continue;
                }
            };
        } else {
            cliclack::log::error(format!("Object 0x{:04x} is not an asymmetric key", key.id))?;
            continue;
        }

        if let Err(err) = write_file(pem_pubkey, &filename) {
            cliclack::log::error(format!("Failed to write public key 0x{:04x} to file. {}",
                                         key.id,
                                         err))?;
        }

        //print_pem_string(ed_pubkey.public_key_to_pem()?);
    }
    Ok(())
}


fn get_hashed_bytes(hash_algo: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
    match hash_algo {
        HashAlgorithm::SHA1 => Ok(openssl::hash::hash(MessageDigest::sha1(), input)?.to_vec()),
        HashAlgorithm::SHA256 => Ok(openssl::hash::hash(MessageDigest::sha256(), input)?.to_vec()),
        HashAlgorithm::SHA384 => Ok(openssl::hash::hash(MessageDigest::sha384(), input)?.to_vec()),
        HashAlgorithm::SHA512 => Ok(openssl::hash::hash(MessageDigest::sha512(), input)?.to_vec()),
    }
}

fn get_mgf1_algorithm(hash_algo: HashAlgorithm) -> ObjectAlgorithm {
    match hash_algo {
        HashAlgorithm::SHA1 => ObjectAlgorithm::Mgf1Sha1,
        HashAlgorithm::SHA256 => ObjectAlgorithm::Mgf1Sha256,
        HashAlgorithm::SHA384 => ObjectAlgorithm::Mgf1Sha384,
        HashAlgorithm::SHA512 => ObjectAlgorithm::Mgf1Sha512,
    }
}

fn get_operation_key(session:&Session, authkey_capabilities: &Vec<ObjectCapability>,
                     op_capabilities: &Vec<ObjectCapability>, key_algo: &[ObjectAlgorithm]) -> Result<ObjectDescriptor, MgmError> {
    let key_capabilities = get_intesected_capabilities(
        authkey_capabilities, op_capabilities);
    if key_capabilities.is_empty() {
        return Err(MgmError::Error("Current user does not have the right capabilities".to_string()))
    }
    let keys = session.list_objects_with_filter(
        0,
        ObjectType::AsymmetricKey,
        "",
        ObjectAlgorithm::ANY,
        &key_capabilities)?;

    if key_algo.is_empty() {
        select_one_object(session, keys, "Select signing key")
    } else {
        let mut descs = Vec::new();
        for k in keys {
            let desc = session.get_object_info(k.object_id, k.object_type)?;
            if key_algo.contains(&desc.algorithm) {
                descs.push(desc);
            }
        }

        if descs.is_empty() {
            return Err(MgmError::Error("No asymmetric keys were found for operation".to_string()));
        }

        let mut key = cliclack::select("Select operational key");
        for desc in descs {
            key = key.item(desc.clone(), BasicDescriptor::from(desc), "");
        }
        Ok(key.interact()?)
    }
}


fn asym_sign(session: &Session, current_authkey: u16) -> Result<(), MgmError> {

    let input_str = match get_format(&vec![InputOutputFormat::STDIN, InputOutputFormat::BINARY])? {
        InputOutputFormat::STDIN => {
            cliclack::input("Data to sign: ").interact()?
        }
        InputOutputFormat::BINARY => {
            read_file_string("Absolute path to file containing data to sign: ")?
        }
        _ => unreachable!()
    };

    let authkey_capabilities = session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities;
    let signing_key = get_operation_key(session, &authkey_capabilities,
                                        [ObjectCapability::SignPkcs, ObjectCapability::SignPss, ObjectCapability::SignEcdsa, ObjectCapability::SignEddsa].to_vec().as_ref(),
                                        &[])?;

    let signed_data;
    if RSA_KEY_ALGORITHM.contains(&signing_key.algorithm) {
        let mut sign_capabiliy = Vec::new();
        if signing_key.capabilities.contains(&ObjectCapability::SignPkcs) &&
            authkey_capabilities.contains(&ObjectCapability::SignPkcs) {
            sign_capabiliy.push(ObjectCapability::SignPkcs);
        }
        if signing_key.capabilities.contains(&ObjectCapability::SignPss) &&
            authkey_capabilities.contains(&ObjectCapability::SignPss) {
            sign_capabiliy.push(ObjectCapability::SignPss);
        }
        let sign_capabiliy =
            if sign_capabiliy.len() == 0 {
                return Err(MgmError::Error("Selected RSA key has no signing capabilities".to_string()))
            } else if sign_capabiliy.len() == 1 {
                sign_capabiliy[0]
            } else if sign_capabiliy.len() == 2 {
                cliclack::select("Select RSA signing algorithm")
                    .item(ObjectCapability::SignPkcs, "RSA-PKCS#1v1.5", "")
                    .item(ObjectCapability::SignPss, "RSA-PSS", "")
                    .interact()?
            } else {
                unreachable!()
            };
        match sign_capabiliy {
            ObjectCapability::SignPkcs => {
                let hash_algo = get_hash_algorithm()?;
                let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                signed_data = session.sign_pkcs1v1_5(signing_key.id, true, hashed_bytes.as_slice())?;
                cliclack::log::success(format!("Signed data with RSA-PKCS#1v1.5 and {}", hash_algo))?;
            }
            ObjectCapability::SignPss => {
                let hash_algo = get_hash_algorithm()?;
                let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                let mgf1_algo = get_mgf1_algorithm(hash_algo);
                signed_data = session.sign_pss(signing_key.id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?;
                cliclack::log::success(format!("Signed data with RSA-PSS and {}", mgf1_algo))?;
            }
            _ => unreachable!()
        }
    } else if EC_KEY_ALGORITHM.contains(&signing_key.algorithm) {
        if signing_key.capabilities.contains(&ObjectCapability::SignEcdsa) &&
            authkey_capabilities.contains(&ObjectCapability::SignEcdsa) {
            let hash_algo = get_hash_algorithm()?;
            let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
            signed_data = session.sign_ecdsa(signing_key.id, hashed_bytes.as_slice())?;
            cliclack::log::success(format!("Signed data with ECDSA and {}", hash_algo))?;
        } else {
            return Err(MgmError::Error("Selected key has no ECDSA signing capabilities".to_string()))
        }
    } else if signing_key.algorithm == ObjectAlgorithm::Ed25519 {
        if signing_key.capabilities.contains(&ObjectCapability::SignEddsa) &&
            authkey_capabilities.contains(&ObjectCapability::SignEddsa) {
            signed_data = session.sign_eddsa(signing_key.id, input_str.as_bytes())?;
            cliclack::log::success("Signed data with EDDSA and")?;
        } else {
            return Err(MgmError::Error("Selected key has no EDDSA signin capabilities".to_string()))
        }
    } else {
        return Err(MgmError::Error("Selected key has no asymmetric signing capabilities".to_string()))
    };

    write_file(signed_data, &"data.sig".to_string())
}

fn asym_decrypt(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let input_bytes = read_file_bytes("Enter path to file containing encrypted data: ")?;

    let authkey_capabilities = session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities;
    let decrypt_key = get_operation_key(session, &authkey_capabilities,
                                        [ObjectCapability::DecryptPkcs, ObjectCapability::DecryptOaep].to_vec().as_ref(),
                                        &RSA_KEY_ALGORITHM)?;

    let dec_data;
    let mut decrypt_capabiliy = Vec::new();
    if decrypt_key.capabilities.contains(&ObjectCapability::DecryptPkcs) &&
        authkey_capabilities.contains(&ObjectCapability::DecryptPkcs) {
        decrypt_capabiliy.push(ObjectCapability::DecryptPkcs);
    }
    if decrypt_key.capabilities.contains(&ObjectCapability::DecryptOaep) &&
        authkey_capabilities.contains(&ObjectCapability::DecryptOaep) {
        decrypt_capabiliy.push(ObjectCapability::DecryptOaep);
    }
    let decrypt_capabiliy =
        if decrypt_capabiliy.len() == 0 {
            return Err(MgmError::Error("Selected RSA key has no decryption capabilities".to_string()))
        } else if decrypt_capabiliy.len() == 1 {
            decrypt_capabiliy[0]
        } else if decrypt_capabiliy.len() == 2 {
            cliclack::select("Select RSA decryption algorithm")
                .item(ObjectCapability::DecryptPkcs, "RSA-PKCS#1v1.5", "")
                .item(ObjectCapability::DecryptOaep, "RSA-OAEP", "")
                .interact()?
        } else {
            unreachable!()
        };
    match decrypt_capabiliy {
        ObjectCapability::DecryptPkcs => {
            dec_data = session.decrypt_pkcs1v1_5(decrypt_key.id, input_bytes.as_slice())?;
            cliclack::log::success("Decrypted data with RSA-PKCS#1v1.5")?;
        }
        ObjectCapability::DecryptOaep => {
            let hash_algo = get_hash_algorithm()?;
            let label = get_hashed_bytes(hash_algo, input_bytes.as_slice())?;
            let mgf1_algo = get_mgf1_algorithm(hash_algo);
            dec_data = session.decrypt_oaep(decrypt_key.id, input_bytes.as_slice(), label.as_slice(), mgf1_algo)?;
            cliclack::log::success(format!("Decrypted data with RSA-OAEP and {}", mgf1_algo))?;
        }
        _ => unreachable!()
    }

    write_file(dec_data, &"data.dec".to_string())
}

fn asym_derive_ecdh(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let authkey_capabilities = session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities;
    let hsm_key = get_operation_key(session, &authkey_capabilities, [ObjectCapability::DeriveEcdh].to_vec().as_ref(), &EC_KEY_ALGORITHM)?;

    let pubkey = openssl::ec::EcKey::public_key_from_pem(read_file_string("Enter path to EC public key PEM file: ")?.as_bytes())?;
    let mut ctx = BigNumContext::new()?;
    let ec_point_ref = pubkey.public_key();
    let ec_group_ref = pubkey.group();
    let ext_key = ec_point_ref.to_bytes(ec_group_ref, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let nid = ec_group_ref.curve_name().ok_or(MgmError::Error(String::from("Failed to find EC curve name")))?;
    let ext_key_algo = get_algo_from_nid(nid)?;

    if hsm_key.algorithm != ext_key_algo {
        return Err(MgmError::Error("External EC public key has a different algorithm from the YubiHSM key".to_string()));
    }
    cliclack::log::success(hex::encode(session.derive_ecdh(hsm_key.id, ext_key.as_slice())?))?;

    Ok(())
}

fn get_asym_java_command(session: &Session, current_authkey: u16) -> Result<AsymJavaCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands = cliclack::select("");
    commands = commands.item(AsymJavaCommand::ListKeys, "List JAVA keys", "");

    if capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::PutOpaque) &&
        capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(AsymJavaCommand::GenerateKey, "Generate JAVA key", "");
    }

    if capabilities.contains(&ObjectCapability::PutAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::PutOpaque) &&
        capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands = commands.item(AsymJavaCommand::ImportKey, "Import JAVA key", "");
    }

    if capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands = commands.item(AsymJavaCommand::DeleteKey, "Delete JAVA key", "");
    }
    commands = commands.item(AsymJavaCommand::ReturnToMenu, "Return to main menu", "");
    Ok(commands.interact()?)
}

fn asym_java_manage(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    cliclack::note("",
                   "A JAVA key is a pair of an asymmetric key and an X509Certificate, both stored on the \
                   YubiHSM using the same ObjectID")?;
    loop {
        let cmd = get_asym_java_command(session, current_authkey)?;
        let res = match cmd {
            AsymJavaCommand::ListKeys => java_list_keys(session),
            AsymJavaCommand::GenerateKey => java_gen_key(session),
            AsymJavaCommand::ImportKey => java_import_key(session),
            AsymJavaCommand::DeleteKey => java_delete_keys(session),
            AsymJavaCommand::ReturnToMenu => break,
        };
        if let Err(err) = res {
            cliclack::log::error(err)?;
        }
    }
    Ok(())
}

fn java_get_all_keys(session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let mut key_handles:Vec<ObjectDescriptor> = Vec::new();
    let cert_handles: Vec<ObjectHandle> = session.list_objects_with_filter(
        0,
        ObjectType::Opaque,
        "",
        ObjectAlgorithm::OpaqueX509Certificate,
        &Vec::new())?;
    for cert in cert_handles {
        if let Ok(object_desc) = session.get_object_info(cert.object_id, ObjectType::AsymmetricKey) {
            key_handles.push(object_desc);
        }
    }
    Ok(key_handles)
}

fn java_list_keys(session: &Session) -> Result<(), MgmError> {
    let all_java_keys = java_get_all_keys(session)?;
    cliclack::log::remark(format!("Found {} objects", all_java_keys.len()))?;
    for key in all_java_keys {
        println!("  {}", BasicDescriptor::from(key));
    }
    Ok(())
}

fn java_delete_keys(session: &Session) -> Result<(), MgmError> {
    let all_java_keys = java_get_all_keys(session)?;

    if all_java_keys.is_empty() {
        cliclack::log::info("No java keys available for removal")?;
        return Ok(());
    }

    let mut selected_keys = cliclack::multiselect(
        "Select JAVA keys to delete. Press the space button to select and unselect item. Press 'Enter' when done.");
    selected_keys = selected_keys.required(false);
    for key in all_java_keys {
        selected_keys = selected_keys.item(key.clone(), BasicDescriptor::from(key), "");
    }
    let selected_keys = selected_keys.interact()?;
    if !selected_keys.is_empty() && cliclack::confirm("Selected key(s) will be deleted and cannot be recovered. Execute?").interact()? {
        for key in selected_keys {
            if let Err(err) = delete_java_key(session, key.id, key.id) {
                cliclack::log::error(format!("Failed to delete object with ID 0x{:04x}. {}", key.id, err))?;
                continue;
            };
        }
    }
    Ok(())
}

fn delete_java_key(session: &Session, key_id: u16, cert_id: u16) -> Result<(), MgmError>{
    session.delete_object(key_id, ObjectType::AsymmetricKey)?;
    cliclack::log::info(
        format!("Deleted asymmetric key with ID 0x{:04x} from the device", key_id))?;
    if cert_id != 0 {
        session.delete_object(cert_id, ObjectType::Opaque)?;
        cliclack::log::info(
            format!("Deleted X509Certificate with ID 0x{:04x} from the device", cert_id))?;
    }
    Ok(())
}

fn java_gen_key(session: &Session) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let key_algorithm: ObjectAlgorithm;
    let mut capabilities: Vec<ObjectCapability> = Vec::new();

    let key_type = cliclack::select("Select key type")
        .item(AsymKeyTypes::RSA, "RSA", "")
        .item(AsymKeyTypes::EC, "EC", "")
        .interact()?;

    if key_type == AsymKeyTypes::RSA {
        let key_len = get_rsa_keylen()?;
        key_algorithm = get_rsa_key_algo(key_len/8)?;

        capabilities.extend(vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::DecryptPkcs,
            ObjectCapability::DecryptOaep,
            ObjectCapability::SignAttestationCertificate,
            ObjectCapability::ExportableUnderWrap,
        ].to_vec());
    } else {
        key_algorithm = get_ec_algo()?;
        capabilities.extend(vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::DeriveEcdh,
            ObjectCapability::SignAttestationCertificate,
            ObjectCapability::ExportableUnderWrap,
        ].to_vec());
    }

    cliclack::note("Generating asymmetric key with:",
                   get_object_properties_str(&key_algorithm, &label, key_id, &domains, &capabilities))?;

    if cliclack::confirm("Execute?").interact()? {
        let key = session
            .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)?;
        cliclack::log::step(
            format!("Stored asymmetric key with ID 0x{:04x} on the device", key.get_key_id()))?;

        // Import attestation certificate template into the device
        let cert = base64::decode_block(ATTESTATION_CERT_TEMPLATE)?;
        let cert_id = match session.import_cert(key.get_key_id(), &label, &domains, &[], &cert) {
            Ok(id) => id,
            Err(err) => {
                cliclack::log::error("Failed to import template X509Certificate. Deleting generated key")?;
                delete_java_key(session, key.get_key_id(), 0)?;
                return Err(MgmError::LibYubiHsm(err))
            }
        };
        if cert_id != key.get_key_id() {
            cliclack::log::error("Faulty import. Deleting generated key")?;
            delete_java_key(session, key.get_key_id(), cert_id)?;
            return Err(MgmError::Error("Failed to store the attestation certificate template using the same ID as the asymmetric key".to_string()));
        }

        // Generate self signed certificate for the asymmetric key
        let selfsigned_cert = match key.sign_attestation_certificate(key.get_key_id(), session) {
            Ok(cert) => cert,
            Err(err) => {
                cliclack::log::error("Failed to sign selfsigned certificate. Deleting generated key")?;
                delete_java_key(session, key.get_key_id(), cert_id)?;
                return Err(MgmError::LibYubiHsm(err));
            }
        };
        cliclack::log::step("Signed selfsigned certificate")?;

        // Delete the attestation template certificate from the device
        if let Err(err) = session.delete_object(cert_id, ObjectType::Opaque) {
            cliclack::log::error("Failed to deleted X509Certificate template and replace with selfsigned certificate. Deleting generated key")?;
            delete_java_key(session, key.get_key_id(), 0)?;
            return Err(MgmError::LibYubiHsm(err))
        }
        cliclack::log::step("Deleted X509Certificate template. Ready to import the selfsigned certificate")?;

        let cert = match session.import_opaque(
            key.get_key_id(),
            &label,
            &*domains,
            &[ObjectCapability::ExportableUnderWrap],
            ObjectAlgorithm::OpaqueX509Certificate,
            &selfsigned_cert) {
            Ok(cert) => cert,
            Err(err) => {
                cliclack::log::error("Failed to import selfsigned certificate. Deleting generated key")?;
                delete_java_key(session, key.get_key_id(), 0)?;
                return Err(MgmError::LibYubiHsm(err))
            }
        };
        if cert.get_id() != key.get_key_id() {
            cliclack::log::error("Faulty import. Deleting generated key")?;
            delete_java_key(session, key.get_key_id(), cert.get_id())?;
            return Err(MgmError::Error("Failed to store X509 certificate with the same ID as the asymmetric key".to_string()))
        }
        cliclack::log::step(
            format!("Stored selfsigned certificate with ID 0x{:04x} on the device", cert.get_id()))?;

        cliclack::log::success(
            format!("Stored JAVA key with ID 0x{:04x} on the device", key.get_key_id()))?;
    }
    Ok(())
}

fn java_import_key(session: &Session ) -> Result<(), MgmError> {
    let mut key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;

    let pem = read_pem_file("Enter absolute path to PEM file containing private key: ")?;
    let key_bytes = pem.contents();

    let mut capabilities: Vec<ObjectCapability> = Vec::new();

    let pkey = openssl::pkey::PKey::private_key_from_der(key_bytes)?;
    match pkey.id() {
        pkey::Id::RSA => {
            cliclack::log::info("Found RSA private key")?;
            let private_rsa = pkey.rsa()?;
            let p = private_rsa.p().ok_or(MgmError::Error(String::from("Failed to read p value")))?;
            let q = private_rsa.q().ok_or(MgmError::Error(String::from("Failed to read q value")))?;

            let key_algorithm = get_rsa_key_algo(private_rsa.size())?;

            capabilities.extend(vec![
                ObjectCapability::SignPkcs,
                ObjectCapability::SignPss,
                ObjectCapability::DecryptPkcs,
                ObjectCapability::DecryptOaep,
                ObjectCapability::SignAttestationCertificate,
                ObjectCapability::ExportableUnderWrap,
            ].to_vec());

            key_id = session
                .import_rsa_key(key_id, &label, &*domains, &capabilities, key_algorithm, &p.to_vec(), &q.to_vec())?
        }
        pkey::Id::EC => {
            cliclack::log::info("Found EC private key")?;
            let private_ec = pkey.ec_key()?;
            let s = private_ec.private_key();
            let group = private_ec.group();
            let nid = group.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
            let key_algorithm = get_algo_from_nid(nid)?;

            capabilities.extend(vec![
                ObjectCapability::SignEcdsa,
                ObjectCapability::DeriveEcdh,
                ObjectCapability::SignAttestationCertificate,
                ObjectCapability::ExportableUnderWrap,
            ].to_vec());
            key_id = session
                .import_ec_key(key_id, &label, &*domains, &capabilities, key_algorithm, &s.to_vec())?
        }
        _ => return Err(MgmError::Error("Found unknown or unsupported key type in PEM file".to_string())),
    };
    cliclack::log::success(
        format!("Imported asymmetric private key with ID 0x{:04x} on the device", key_id))?;


    let pem = read_pem_file("Enter absolute path to PEM file containing X509Certificate:")?;
    let cert_bytes = pem.contents();

    match openssl::x509::X509::from_der(cert_bytes) {
        Ok(cert) => {
            let cert_id = match session
                .import_cert(key_id, &label, &*domains, &[ObjectCapability::ExportableUnderWrap], &cert.to_pem()?) {
                Ok(id) => id,
                Err(err) => {
                    cliclack::log::error("Failed to import X509Certificate from file. Deleting imported key")?;
                    delete_java_key(session, key_id, 0)?;
                    return Err(MgmError::LibYubiHsm(err))
                }
            };
            if cert_id != key_id {
                cliclack::log::error("Faulty import. Deleting imported key")?;
                delete_java_key(session, key_id, cert_id)?;
                return Err(MgmError::Error("Failed to store X509 certificate with the same ID as the asymmetric key".to_string()))
            }

            cliclack::log::success(format!("Imported X509Certificate with ID 0x{:04x} on the device", key_id))?;
        }
        Err(cert_err) => {
            cliclack::log::error("No X509Certificate found. Deleting imported key")?;
            session.delete_object(key_id, ObjectType::AsymmetricKey)?;
            return Err(MgmError::OpenSSLError(cert_err));
        }
    }

    Ok(())
}