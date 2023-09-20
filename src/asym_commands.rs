use std::cmp::Ordering;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::io::{stdout, Write};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::{base64, pkey};
use openssl::pkey::{PKey};
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects, read_file};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDescriptor, get_common_properties, get_filtered_objects, get_integer_or_default, MultiSelectItem, print_object_properties, read_file_bytes, select_object_capabilities, write_file};

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


#[derive(Debug, Clone, Copy)]
enum AsymCommand {
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
    GetPublicKey,
    DeleteKey,
    PerformSignature,
    PerformRsaDecryption,
    DeriveEcdh,
    ManageJavaKeys,
    Exit,
}

#[derive(Debug, Clone, Copy)]
enum AsymJavaCommand {
    ListKeys,
    GenerateKey,
    ImportKey,
    DeleteKey,
    ReturnToMenu,
    Exit,
}

#[derive(Debug, Clone, Copy)]
enum AsymKeyTypes {
    RSA,
    EC,
    ED,
}

#[derive(Debug, Clone, Copy)]
enum SignAlgorithm {
    PKCS1,
    PSS,
    ECDSA,
    EDDSA,
}

#[derive(Debug, Clone, Copy)]
enum DecryptAlgorithm {
    PKCS1,
    OAEP,
}

#[derive(Debug, Clone, Copy)]
enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug, Clone, Copy)]
enum InputOutputFormat {
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
        stdout().flush().unwrap();
        let cmd = get_asym_command(session, current_authkey)?;
        match cmd {
            AsymCommand::ListKeys => asym_list_keys(session)?,
            AsymCommand::GetKeyProperties => asym_get_key_properties(session)?,
            AsymCommand::GenerateKey => asym_gen_key(session, current_authkey)?,
            AsymCommand::ImportKey => asym_import_key(session, current_authkey)?,
            AsymCommand::DeleteKey => asym_delete_key(session)?,
            AsymCommand::GetPublicKey => asym_get_public_key(session)?,
            AsymCommand::PerformSignature => asym_sign(session)?,
            AsymCommand::PerformRsaDecryption => asym_decrypt(session)?,
            AsymCommand::DeriveEcdh => asym_derive_ecdh(session)?,
            AsymCommand::ManageJavaKeys => asym_java_manage(session, current_authkey)?,
            AsymCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        }
    }
}

fn get_asym_command(session: &Session, current_authkey: u16) -> Result<AsymCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands: Vec<(String, AsymCommand)> = Vec::new();
    commands.push(("List keys".to_string(), AsymCommand::ListKeys));
    commands.push(("Get key properties".to_string(), AsymCommand::GetKeyProperties));
    if capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) {
        commands.push(("Generate key".to_string(), AsymCommand::GenerateKey));
    }
    if capabilities.contains(&ObjectCapability::PutAsymmetricKey) {
        commands.push(("Import key".to_string(), AsymCommand::ImportKey));
    }
    if capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) ||
        capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands.push(("Delete key".to_string(), AsymCommand::DeleteKey));
    }
    commands.push(("Get public key".to_string(), AsymCommand::GetPublicKey));
    if HashSet::from([ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa]).intersection(&capabilities).count() > 0 {
        commands.push(("Perform signature".to_string(), AsymCommand::PerformSignature));
    }
    if HashSet::from([
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep]).intersection(&capabilities).count() > 0 {
        commands.push(("Perform RSA decryption".to_string(), AsymCommand::PerformRsaDecryption));
    }
    if capabilities.contains(&ObjectCapability::DeriveEcdh) {
        commands.push(("Derive ECDH".to_string(), AsymCommand::DeriveEcdh));
    }
    if HashSet::from([
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::PutAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey]).intersection(&capabilities).count() > 0
        &&
        HashSet::from([
            ObjectCapability::PutOpaque,
            ObjectCapability::DeleteOpaque]).intersection(&capabilities).count() > 0 {
        commands.push(("Manage JAVA keys (Usable with SunPKCS11 provider)".to_string(), AsymCommand::ManageJavaKeys));
    }
    commands.push(("Exit".to_string(), AsymCommand::Exit));
    println!();
    Ok(get_menu_option(&commands))
}

fn get_asym_keytype() -> AsymKeyTypes {
    println!("\n  Choose key type:");
    let types: [(String, AsymKeyTypes); 3] = [
        ("RSA".to_string(), AsymKeyTypes::RSA),
        ("EC".to_string(), AsymKeyTypes::EC),
        ("ED".to_string(), AsymKeyTypes::ED)];
    get_menu_option(&types.to_vec())
}

fn get_sign_algo() -> SignAlgorithm {
    println!("\n  Sign using:");
    let algos: [(String, SignAlgorithm); 4] = [
        ("RSA-PKCS#1v1.5".to_string(), SignAlgorithm::PKCS1),
        ("RSA-PSS".to_string(), SignAlgorithm::PSS),
        ("ECDSA".to_string(), SignAlgorithm::ECDSA),
        ("EDDSA".to_string(), SignAlgorithm::EDDSA), ];
    get_menu_option(&algos.to_vec())
}

fn get_decrypt_algo() -> DecryptAlgorithm {
    println!("\n  Decrypt using:");
    let algos: [(String, DecryptAlgorithm); 2] = [
        ("RSA-PKCS#1v1.5".to_string(), DecryptAlgorithm::PKCS1),
        ("RSA-OAEP".to_string(), DecryptAlgorithm::OAEP)];
    get_menu_option(&algos.to_vec())
}

fn get_hash_algorithm() -> HashAlgorithm {
    println!("\n  Choose hash algorithm:");
    let types: [(String, HashAlgorithm); 4] = [
        ("SHA1".to_string(), HashAlgorithm::SHA1),
        ("SHA256".to_string(), HashAlgorithm::SHA256),
        ("SHA384".to_string(), HashAlgorithm::SHA384),
        ("SHA512".to_string(), HashAlgorithm::SHA512)];
    get_menu_option(&types.to_vec())
}

fn get_format(supported_formats: &Vec<InputOutputFormat>) -> InputOutputFormat {
    println!("\n  Choose input_format:");
    let mut items: Vec<(String, InputOutputFormat)> = Vec::new();
    for f in supported_formats {
        items.push((f.to_string(), f.clone()));
    }
    get_menu_option(&items)
}

fn get_ec_algo() -> ObjectAlgorithm {
    println!("\n  Choose EC Curve:");
    let curves: [(String, ObjectAlgorithm); 8] = [
        ("secp224r1".to_string(), ObjectAlgorithm::EcP224),
        ("secp256r1".to_string(), ObjectAlgorithm::EcP256),
        ("secp384r1".to_string(), ObjectAlgorithm::EcP384),
        ("secp521r1".to_string(), ObjectAlgorithm::EcP521),
        ("secp256k1".to_string(), ObjectAlgorithm::EcK256),
        ("brainpool256r1".to_string(), ObjectAlgorithm::EcBp256),
        ("brainpool384r1".to_string(), ObjectAlgorithm::EcBp384),
        ("brainpool512r1".to_string(), ObjectAlgorithm::EcBp512)];
    get_menu_option(&curves.to_vec())
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
            println!("Unrecognized EC curve");
            Err(MgmError::InvalidInput(format!("EC curve {:?}", nid)))
        }
    }
}

fn get_rsa_keylen() -> u32 {
    let accepted_len = vec![2048, 3072, 4096];
    let mut key_len: u32 = 0;
    while !accepted_len.contains(&key_len) {
        key_len = get_integer_or_default("Enter key length [2048, 3072, 4096] [defualt 2048]: ", 2048);
    }
    key_len
}

fn get_rsa_key_algo(size_in_bytes:u32) -> Result<ObjectAlgorithm, MgmError> {
    match size_in_bytes {
        256 => Ok(ObjectAlgorithm::Rsa2048),
        384 => Ok(ObjectAlgorithm::Rsa3072),
        512 => Ok(ObjectAlgorithm::Rsa4096),
        _ => {
            println!("Unsupported RSA key size");
            Err(MgmError::Error(format!("RSA key size {} bytes", size_in_bytes)))
        }
    }
}

fn asym_gen_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    println!();
    let (key_id, label, domains) = get_common_properties();

    let permissible_capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities.expect("Cannot read current authentication key's delegated capabilities")
            .into_iter().collect();


    let key_algorithm: ObjectAlgorithm;
    let mut capabilities: Vec<ObjectCapability> = Vec::new();

    match get_asym_keytype() {
        AsymKeyTypes::RSA => {
            let key_len = get_rsa_keylen();
            key_algorithm = get_rsa_key_algo(key_len/8)?;
            capabilities = select_object_capabilities(&HashSet::from(RSA_KEY_CAPABILITIES), &permissible_capabilities);
        }
        AsymKeyTypes::EC => {
            key_algorithm = get_ec_algo();
            capabilities = select_object_capabilities(&HashSet::from(EC_KEY_CAPABILITIES), &permissible_capabilities);
        }
        AsymKeyTypes::ED => {
            key_algorithm = ObjectAlgorithm::Ed25519;
            capabilities = select_object_capabilities(&HashSet::from(ED_KEY_CAPABILITIES), &permissible_capabilities);
        }
    };

    println!("\n  Generating asymmetric key with:");
    println!("    Key algorithm: {}", key_algorithm);
    println!("    Label: {}", label);
    println!("    Key ID: {}", key_id);
    print!("    Domains: ");
    domains.iter().for_each(|domain| print!("{}, ", domain));
    println!();
    print!("    Capabilities: ");
    capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!("\n\n");

    if bool::from(get_boolean_answer("Execute? ")) {
        let key = session
            .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)?;
        println!("  Generated asymmetric keypair with ID 0x{:04x} on the device", key.get_key_id());
    }
    Ok(())
}

fn asym_import_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    println!();
    let (mut key_id, label, domains) = get_common_properties();

    let mut pem = pem::parse(read_file("Enter absolute path to PEM file: "));
    while pem.is_err() {
        println!("Unable to parse PEM content: {}", pem.err().unwrap());
        pem = pem::parse(read_file("Enter absolute path to PEM file: "));
    }
    let pem = pem.unwrap();
    let key_bytes = pem.contents();

    let permissible_capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities.expect("Cannot read current authentication key's delegated capabilities")
            .into_iter().collect();

    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            match key.id() {
                pkey::Id::RSA => {
                    println!("RSA key");
                    let private_rsa = key.rsa()?;
                    let p = private_rsa.p().ok_or(MgmError::Error(String::from("Failed to read p value")))?;
                    let q = private_rsa.q().ok_or(MgmError::Error(String::from("Failed to read q value")))?;
                    let key_algorithm = get_rsa_key_algo(private_rsa.size())?;

                    let capabilities = select_object_capabilities(&HashSet::from(RSA_KEY_CAPABILITIES), &permissible_capabilities);


                    key_id = session
                        .import_rsa_key(key_id, &label, &*domains, &capabilities, key_algorithm, &p.to_vec(), &q.to_vec())?
                }
                pkey::Id::EC => {
                    let private_ec = key.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let nid = group.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
                    let key_algorithm = get_algo_from_nid(nid)?;
                    let capabilities = select_object_capabilities(&HashSet::from(EC_KEY_CAPABILITIES), &permissible_capabilities);

                    key_id = session
                        .import_ec_key(key_id, &label, &*domains, &capabilities, key_algorithm, &s.to_vec())?
                }
                pkey::Id::ED25519 => {
                    let private_ed = PKey::private_key_from_raw_bytes(key_bytes, openssl::pkey::Id::ED25519)?;
                    let k = private_ed.raw_private_key()?;
                    let capabilities = select_object_capabilities(&HashSet::from(ED_KEY_CAPABILITIES), &permissible_capabilities);
                    key_id = session
                        .import_ed_key(key_id, &label, &*domains, &capabilities, &k.to_vec())?
                }
                _ => println!("Unknown key type"),
            }
            println!("\n  Imported asymmetric keypair with ID 0x{:04x} on the device", key_id);
        }
        Err(err) => {
            let key_err = err;
            println!("Not a key. Trying to import as X509 certificate");
            match openssl::x509::X509::from_der(&key_bytes) {
                Ok(cert) => {
                    key_id = session
                        .import_cert(key_id, &label, &*domains, &cert.to_pem().unwrap())?;
                    println!("\n  Imported X509Certificate with ID 0x{:04x} on the device", key_id)
                }
                Err(cert_err) => {
                    println!("  {}", key_err);
                    println!("  {}", cert_err);
                    return Err(MgmError::Error(String::from("Error! Failed to find either private key or X509Certificate")));
                }
            }
        }
    };
    Ok(())
}

fn asym_list_keys(session: &Session) -> Result<(), MgmError> {
    let key_handles: Vec<ObjectHandle> = get_filtered_objects(session, ObjectType::AsymmetricKey, true)?;
    println!("Found {} objects", key_handles.len());
    for object in key_handles {
        println!("  {}", session.get_object_info(object.object_id, object.object_type)?);
    }
    Ok(())
}

fn asym_get_key_properties(session: &Session) -> Result<(), MgmError> {
    println!();
    if bool::from(get_boolean_answer("Is certificate?")) {
        print_object_properties(session, ObjectType::Opaque);
    } else {
        print_object_properties(session, ObjectType::AsymmetricKey);
    }
    Ok(())
}

fn asym_delete_key(session: &Session) -> Result<(), MgmError> {
    let keys = get_filtered_objects(session, ObjectType::AsymmetricKey, true)?;
    delete_objects(session, keys)
}

fn print_pem_string(pem_bytes: Vec<u8>) {
    println!();
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

fn asym_get_public_key(session: &Session) -> Result<(), MgmError> {
    let keys = get_filtered_objects(session, ObjectType::AsymmetricKey, false)?;
    let mut pubkeys: Vec<(Vec<u8>, ObjectAlgorithm)> = Vec::new();
    match keys.len().cmp(&usize::try_from(1).unwrap()) {
        Ordering::Equal => pubkeys.push(session.get_pubkey(keys[0].object_id)?),
        Ordering::Greater => {
            let mut key_options: Vec<MultiSelectItem<BasicDescriptor>> = Vec::new();
            for handle in keys {
                key_options.push(MultiSelectItem { item: BasicDescriptor::from(session.get_object_info(handle.object_id, handle.object_type)?), selected: false });
            }
            let selected_keys = get_selected_items(&mut key_options);
            for desc in selected_keys {
                pubkeys.push(session.get_pubkey(desc.object_id)?);
            }
        }
        Ordering::Less => println!("No keys were found"),
    };

    for pubkey in pubkeys {
        let key_algo = pubkey.1;
        if [ObjectAlgorithm::Rsa2048, ObjectAlgorithm::Rsa3072, ObjectAlgorithm::Rsa4096].contains(&key_algo) {
            let e = BigNum::from_slice(&[0x01, 0x00, 0x01]).unwrap();
            let n = BigNum::from_slice(pubkey.0.as_slice())?;
            let rsa_pubkey = openssl::rsa::Rsa::from_public_components(n, e)?;
            write_file(rsa_pubkey.public_key_to_pem()?, "rsa_pubkey.pem".to_string())?;
            //print_pem_string(rsa_pubkey.public_key_to_pem()?);
        } else if [ObjectAlgorithm::EcP224, ObjectAlgorithm::EcP256, ObjectAlgorithm::EcP384,
            ObjectAlgorithm::EcP521, ObjectAlgorithm::EcK256, ObjectAlgorithm::EcBp256,
            ObjectAlgorithm::EcBp384, ObjectAlgorithm::EcBp512].contains(&key_algo) {
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
            let ec_group = EcGroup::from_curve_name(nid)?;
            let mut ctx = BigNumContext::new()?;
            let mut ec_pubkey_bytes: Vec<u8> = Vec::new();
            ec_pubkey_bytes.push(0x04);
            ec_pubkey_bytes.extend(pubkey.0);
            let ec_point = EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx)?;

            let ec_pubkey = EcKey::from_public_key(&ec_group, &ec_point)?;
            write_file(ec_pubkey.public_key_to_pem()?, "ec_pubkey.pem".to_string())?;
            //print_pem_string(ec_pubkey.public_key_to_pem()?);
        } else if key_algo == ObjectAlgorithm::Ed25519 {
            let ed_pubkey = PKey::public_key_from_raw_bytes(pubkey.0.as_slice(), pkey::Id::ED25519)?;
            write_file(ed_pubkey.public_key_to_pem()?, "ed_pubkey.pem".to_string())?;
            //print_pem_string(ed_pubkey.public_key_to_pem()?);
        } else {
            return Err(MgmError::Error("Object found was not an asymmetric key".to_string()));
        }
    }
    Ok(())
}


fn get_hashed_bytes(hash_algo: HashAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
    let digest: DigestBytes;
    match hash_algo {
        HashAlgorithm::SHA1 => digest = openssl::hash::hash(MessageDigest::sha1(), input)?,
        HashAlgorithm::SHA256 => digest = openssl::hash::hash(MessageDigest::sha256(), input)?,
        HashAlgorithm::SHA384 => digest = openssl::hash::hash(MessageDigest::sha384(), input)?,
        HashAlgorithm::SHA512 => digest = openssl::hash::hash(MessageDigest::sha512(), input)?,
    }
    Ok(digest.to_vec())
}

fn get_mgf1_algorithm(hash_algo: HashAlgorithm) -> ObjectAlgorithm {
    match hash_algo {
        HashAlgorithm::SHA1 => ObjectAlgorithm::Mgf1Sha1,
        HashAlgorithm::SHA256 => ObjectAlgorithm::Mgf1Sha256,
        HashAlgorithm::SHA384 => ObjectAlgorithm::Mgf1Sha384,
        HashAlgorithm::SHA512 => ObjectAlgorithm::Mgf1Sha512,
    }
}


fn get_operation_key(session: &Session, capability: ObjectCapability) -> Result<BasicDescriptor, MgmError> {
    println!("\n  Choose signing or decryption key: ");
    let sign_capabilities: [ObjectCapability; 1] = [capability];
    let key_handles = session.list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &sign_capabilities.to_vec())?;
    let mut key_options: Vec<(String, BasicDescriptor)> = Vec::new();
    for handle in key_handles {
        let option = BasicDescriptor::from(session.get_object_info(handle.object_id, handle.object_type)?);
        key_options.push((option.to_string(), option));
    }
    let chosen = get_menu_option(&key_options);
    Ok(chosen)
}


fn asym_sign(session: &Session) -> Result<(), MgmError> {
    let mut input_str = "".to_string();

    match get_format(&vec![InputOutputFormat::STDIN, InputOutputFormat::BINARY]) {
        InputOutputFormat::STDIN => {
            input_str = get_string("\nData to sign: ");
        }
        InputOutputFormat::BINARY => {
            input_str = read_file("\nAbsolute path to file containing data to sign: ");
        }
        _ => unreachable!()
    }

    let signed_data = match get_sign_algo() {
        SignAlgorithm::PKCS1 => {
            let hash_algo = get_hash_algorithm();
            let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
            let signing_key = get_operation_key(session, ObjectCapability::SignPkcs)?;
            session.sign_pkcs1v1_5(signing_key.object_id, true, hashed_bytes.as_slice())?
        }
        SignAlgorithm::PSS => {
            let hash_algo = get_hash_algorithm();
            let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
            let mgf1_algo = get_mgf1_algorithm(hash_algo);
            let signing_key = get_operation_key(session, ObjectCapability::SignPss)?;
            session.sign_pss(signing_key.object_id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?
        }
        SignAlgorithm::ECDSA => {
            let hash_algo = get_hash_algorithm();
            let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
            let signing_key = get_operation_key(session, ObjectCapability::SignEcdsa)?;
            session.sign_ecdsa(signing_key.object_id, hashed_bytes.as_slice())?
        }
        SignAlgorithm::EDDSA => {
            let signing_key = get_operation_key(session, ObjectCapability::SignEddsa)?;
            session.sign_eddsa(signing_key.object_id, input_str.as_bytes())?
        }
    };

    write_file(signed_data, "data.sig".to_string())?;
    Ok(())
}

fn asym_decrypt(session: &Session) -> Result<(), MgmError> {
    let input_bytes = read_file_bytes("\nAbsolute path to file containing encrypted data: ");

    let decrypted_data = match get_decrypt_algo() {
        DecryptAlgorithm::PKCS1 => {
            let decryption_key = get_operation_key(session, ObjectCapability::DecryptPkcs)?;
            session.decrypt_pkcs1v1_5(decryption_key.object_id, input_bytes.as_slice())?
        }
        DecryptAlgorithm::OAEP => {
            println!("\n  Choose OAEP decryption algorithm:");
            let hash_algos: [(String, HashAlgorithm); 4] = [
                ("RSA OAEP SHA1".to_string(), HashAlgorithm::SHA1),
                ("RSA OAEP SHA256".to_string(), HashAlgorithm::SHA256),
                ("RSA OAEP SHA384".to_string(), HashAlgorithm::SHA384),
                ("RSA OAEP SHA512".to_string(), HashAlgorithm::SHA512)];
            let hash_algo = get_menu_option(&hash_algos.to_vec());
            let label = get_hashed_bytes(hash_algo, input_bytes.as_slice())?;
            let mgf1_algo = get_mgf1_algorithm(hash_algo);
            let decryption_key = get_operation_key(session, ObjectCapability::DecryptOaep)?;
            session.decrypt_oaep(decryption_key.object_id, input_bytes.as_slice(), label.as_slice(), mgf1_algo)?
        }
    };

    write_file(decrypted_data, "data.dec".to_string())?;

    Ok(())
}

fn asym_derive_ecdh(session: &Session) -> Result<(), MgmError> {
    let pubkey = openssl::ec::EcKey::public_key_from_pem(read_file("Enter absolute path to EC public key PEM file: ").as_bytes())?;
    let ec_point_ref = pubkey.public_key();
    let ec_group_ref = pubkey.group();
    let mut ctx = BigNumContext::new()?;
    let ext_key = ec_point_ref.to_bytes(ec_group_ref, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let nid = ec_group_ref.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
    let ext_key_algo = get_algo_from_nid(nid)?;

    let hsm_key = get_operation_key(session, ObjectCapability::DeriveEcdh)?;

    if hsm_key.object_algorithm != ext_key_algo {
        return Err(MgmError::Error("External EC public key has a different algorithm the the YubiHSM key".to_string()));
    }

    let ecdh = session.derive_ecdh(hsm_key.object_id, ext_key.as_slice())?;
    for b in ecdh {
        print!("{b:02x}");
    }
    println!();

    Ok(())
}

fn get_asym_java_command(session: &Session, current_authkey: u16) -> Result<AsymJavaCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands: Vec<(String, AsymJavaCommand)> = Vec::new();
    commands.push(("List JAVA keys".to_string(), AsymJavaCommand::ListKeys));

    if capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::PutOpaque) &&
        capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands.push(("Generate JAVA key".to_string(), AsymJavaCommand::GenerateKey));
    }

    if capabilities.contains(&ObjectCapability::PutAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::PutOpaque) &&
        capabilities.contains(&ObjectCapability::SignAttestationCertificate) {
        commands.push(("Import JAVA key".to_string(), AsymJavaCommand::ImportKey));
    }

    if capabilities.contains(&ObjectCapability::DeleteAsymmetricKey) &&
        capabilities.contains(&ObjectCapability::DeleteOpaque) {
        commands.push(("Delete JAVA key".to_string(), AsymJavaCommand::DeleteKey));
    }
    commands.push(("Return to main menu".to_string(), AsymJavaCommand::ReturnToMenu));
    commands.push(("Exit".to_string(), AsymJavaCommand::Exit));
    println!();
    Ok(get_menu_option(&commands))
}

fn asym_java_manage(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    stdout().flush().unwrap();
    println!("\n  A JAVA key is a pair of an asymmetric key and an X509Certificate, both stored on the YubiHSM using the same ObjectID");
    loop {
        let cmd = get_asym_java_command(session, current_authkey)?;
        match cmd {
            AsymJavaCommand::ListKeys => java_list_keys(session)?,
            AsymJavaCommand::GenerateKey => java_gen_key(session)?,
            AsymJavaCommand::ImportKey => java_import_key(session)?,
            AsymJavaCommand::DeleteKey => java_delete_keys(session)?,
            AsymJavaCommand::ReturnToMenu => break,
            AsymJavaCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        }
    }
    Ok(())
}

fn java_get_all_keys(session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let mut key_handles:Vec<ObjectDescriptor> = Vec::new();
    let cert_handles: Vec<ObjectHandle> = session.list_objects_with_filter(0, ObjectType::Opaque, "", ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?;
    for cert in cert_handles {
        if let Ok(object_desc) = session.get_object_info(cert.object_id, ObjectType::AsymmetricKey) {
            key_handles.push(object_desc);
        }
    }
    Ok(key_handles)
}

fn java_list_keys(session: &Session) -> Result<(), MgmError> {
    let all_java_keys = java_get_all_keys(session)?;
    println!("Found {} objects", all_java_keys.len());
    for key in all_java_keys {
        println!("{}", key);
    }
    Ok(())
}

fn java_delete_keys(session: &Session) -> Result<(), MgmError> {
    let mut key_options: Vec<MultiSelectItem<ObjectDescriptor>> = Vec::new();
    for k in java_get_all_keys(session)? {
        key_options.push(MultiSelectItem { item: k, selected: false });
    }

    for k in get_selected_items(&mut key_options) {
        session.delete_object(k.id, k.object_type)?;
        session.delete_object(k.id, ObjectType::Opaque)?;
        println!("Deleted asymmetric key and X509 certificate with id 0x{:04x}", k.id);
    }

    Ok(())
}

fn java_gen_key(session: &Session) -> Result<(), MgmError> {
    println!();
    let (key_id, label, domains) = get_common_properties();


    let key_algorithm: ObjectAlgorithm;
    let mut capabilities: Vec<ObjectCapability> = Vec::new();

    if bool::from(get_boolean_answer("Is RSA key? ")) {
        let key_len = get_rsa_keylen();
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
        key_algorithm = get_ec_algo();
        capabilities.extend(vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::DeriveEcdh,
            ObjectCapability::SignAttestationCertificate,
            ObjectCapability::ExportableUnderWrap,
        ].to_vec());
    }

    println!("\n  Generating asymmetric key with:");
    println!("    Key algorithm: {}", key_algorithm);
    println!("    Label: {}", label);
    println!("    Key ID: {}", key_id);
    print!("    Domains: ");
    domains.iter().for_each(|domain| print!("{}, ", domain));
    println!();
    print!("    Capabilities: ");
    capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!("\n\n");

    if bool::from(get_boolean_answer("Execute? ")) {
        let key = session
            .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)?;

        // Import attestation certificate template into the device
        let cert = base64::decode_block(ATTESTATION_CERT_TEMPLATE).unwrap();
        let cert_id = session.import_cert(key.get_key_id(), &label, &*domains, &cert)?;
        if cert_id != key.get_key_id() {
            println!("Failed to store the attestation certificate template with the same ID as the asymmetric key");
            session.delete_object(key.get_key_id(), ObjectType::AsymmetricKey)?;
            session.delete_object(cert_id, ObjectType::Opaque)?;
            return Err(MgmError::Error(String::from("Failed to store the attestation certificate template with the same ID as the asymmetric key")));
        }

        // Generate self signed certificate for the asymmetric key
        let selfsigned_cert = key.sign_attestation_certificate(key.get_key_id(), session)?;

        // Delete the attestation template certificate from the device
        session.delete_object(cert_id, ObjectType::Opaque)?;

        let cert = session.import_opaque(key.get_key_id(), &label, &*domains, &[ObjectCapability::ExportableUnderWrap], ObjectAlgorithm::OpaqueX509Certificate, &selfsigned_cert)?;
        if cert.get_id() != key.get_key_id() {
            println!("Failed to store X509 certificate with the same ID as the asymmetric key");
            session.delete_object(key.get_key_id(), ObjectType::AsymmetricKey)?;
            session.delete_object(cert.get_id(), ObjectType::Opaque)?;
            return Err(MgmError::Error(String::from("Failed to store X509 certificate with the same ID as the asymmetric key")));
        }

        println!("Stored selfsigned certificate with ID 0x{:04x} on the device", cert.get_id());
    }
    Ok(())
}

fn java_import_key(session: &Session ) -> Result<(), MgmError> {
    println!();
    let (mut key_id, label, domains) = get_common_properties();

    let mut pem = pem::parse(read_file("Enter absolute path to PEM file containing private key: "));
    while pem.is_err() {
        println!("Unable to parse PEM content: {}", pem.err().unwrap());
        pem = pem::parse(read_file("Enter absolute path to PEM file: "));
    }
    let pem = pem.unwrap();
    let key_bytes = pem.contents();

    let mut capabilities: Vec<ObjectCapability> = Vec::new();

    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            match key.id() {
                pkey::Id::RSA => {
                    println!("RSA key");
                    let private_rsa = key.rsa()?;
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
                    let private_ec = key.ec_key()?;
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
                _ => println!("Unknown or unsupported key type"),
            }
            println!("\n  Imported asymmetric keypair with ID 0x{:04x} on the device", key_id);
        }
        Err(err) => {
            println!("  {}", err);
            return Err(MgmError::Error(String::from("Error! Failed to find either private key in file")));
        }
    };


    let mut pem_cert = pem::parse(read_file("Enter absolute path to PEM file containing X509Certificate: "));
    while pem_cert.is_err() {
        println!("Unable to parse PEM content: {}", pem_cert.err().unwrap());
        pem_cert = pem::parse(read_file("Enter absolute path to PEM file: "));
    }
    let pem_cert = pem_cert.unwrap();
    let cert_bytes = pem_cert.contents();

    match openssl::x509::X509::from_der(&cert_bytes) {
        Ok(cert) => {
            key_id = session
                .import_cert(key_id, &label, &*domains, &cert.to_pem().unwrap())?;
            println!("\n  Imported X509Certificate with ID 0x{:04x} on the device", key_id)
        }
        Err(cert_err) => {
            println!("  {}", cert_err);
            session.delete_object(key_id, ObjectType::AsymmetricKey)?;
            return Err(MgmError::Error(String::from("Error! Failed to find X509Certificate in file")));
        }
    }

    Ok(())
}