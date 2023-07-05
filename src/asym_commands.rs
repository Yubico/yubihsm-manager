use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::io::{stdout, Write};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey;
use openssl::pkey::{PKey, Public};
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDiscriptor, get_common_properties, get_filtered_objects, get_integer_or_default, get_string_or_default, MultiSelectItem, print_object_properties, read_file_bytes, write_file};


#[derive(Debug, Clone, Copy)]
enum AsymCommands {
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


pub fn exec_asym_command(session: Option<&Session>) -> Result<(), MgmError> {
    stdout().flush().unwrap();
    let cmd = get_asym_command();
    match cmd {
        AsymCommands::ListKeys => asym_list_keys(session),
        AsymCommands::GetKeyProperties => asym_get_key_properties(session),
        AsymCommands::GenerateKey => asym_gen_key(session),
        AsymCommands::ImportKey => asym_import_key(session),
        AsymCommands::DeleteKey => asym_delete_key(session),
        AsymCommands::GetPublicKey => asym_get_public_key(session),
        AsymCommands::PerformSignature => asym_sign(session),
        AsymCommands::PerformRsaDecryption => asym_decrypt(session),
        AsymCommands::DeriveEcdh => asym_derive_ecdh(session),
        AsymCommands::Exit => std::process::exit(0),
        _ => unreachable!()
    }
}

fn get_asym_command() -> AsymCommands {
    println!();
    let commands: [(String, AsymCommands);11] = [
        ("List keys".to_string(), AsymCommands::ListKeys),
        ("Get key properties".to_string(), AsymCommands::GetKeyProperties),
        ("Generate key".to_string(), AsymCommands::GenerateKey),
        ("Import key".to_string(), AsymCommands::ImportKey),
        ("Delete key".to_string(), AsymCommands::DeleteKey),
        ("Get public key".to_string(), AsymCommands::GetPublicKey),
        ("Perform signature".to_string(), AsymCommands::PerformSignature),
        ("Perform RSA decryption".to_string(), AsymCommands::PerformRsaDecryption),
        ("Derive ECDH".to_string(), AsymCommands::DeriveEcdh),
        ("Manage JAVA keys (Usable with SunPKCS11 provider) (Not supported yet)".to_string(), AsymCommands::ManageJavaKeys),
        ("Exit".to_string(), AsymCommands::Exit)];
    get_menu_option(&commands.to_vec())
}

fn get_asym_keytype() -> AsymKeyTypes {
    println!("\n  Choose key type:");
    let types: [(String, AsymKeyTypes);3] = [
        ("RSA".to_string(), AsymKeyTypes::RSA),
        ("EC".to_string(), AsymKeyTypes::EC),
        ("ED".to_string(), AsymKeyTypes::ED)];
    get_menu_option(&types.to_vec())
}

fn get_sign_algo() -> SignAlgorithm {
    println!("\n  Sign using:");
    let algos: [(String, SignAlgorithm);4] = [
        ("RSA-PKCS#1v1.5".to_string(), SignAlgorithm::PKCS1),
        ("RSA-PSS".to_string(), SignAlgorithm::PSS),
        ("ECDSA".to_string(), SignAlgorithm::ECDSA),
        ("EDDSA".to_string(), SignAlgorithm::EDDSA),];
    get_menu_option(&algos.to_vec())
}

fn get_decrypt_algo() -> DecryptAlgorithm {
    println!("\n  Decrypt using:");
    let algos: [(String, DecryptAlgorithm);2] = [
        ("RSA-PKCS#1v1.5".to_string(), DecryptAlgorithm::PKCS1),
        ("RSA-OAEP".to_string(), DecryptAlgorithm::OAEP)];
    get_menu_option(&algos.to_vec())
}

fn get_hash_algorithm() -> HashAlgorithm {
    println!("\n  Choose hash algorithm:");
    let types: [(String, HashAlgorithm);4] = [
        ("SHA1".to_string(), HashAlgorithm::SHA1),
        ("SHA256".to_string(), HashAlgorithm::SHA256),
        ("SHA384".to_string(), HashAlgorithm::SHA384),
        ("SHA512".to_string(), HashAlgorithm::SHA512)];
    get_menu_option(&types.to_vec())
}

fn get_format(supported_formats: &Vec<InputOutputFormat>) -> InputOutputFormat {
    println!("\n  Choose input_format:");
    let mut items:Vec<(String, InputOutputFormat)> = Vec::new();
    for f in supported_formats {
        items.push((f.to_string(), f.clone()));
    }
    get_menu_option(&items)
}

fn get_ec_algo() -> ObjectAlgorithm {
    println!("\n  Choose EC Curve:");
    let curves: [(String, ObjectAlgorithm);8] = [
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
        },
    }
}

fn get_rsa_keylen() -> u32 {
    let accepted_len = vec![2048, 3072, 4096];
    let mut key_len:u32 = 0;
    while !accepted_len.contains(&key_len){
        key_len = get_integer_or_default("Enter key length [2048, 3072, 4096] [defualt 2048]: ", 2048);
    }
    key_len
}

fn get_rsakey_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<MultiSelectItem<ObjectCapability>> = vec![
        MultiSelectItem{item: ObjectCapability::SignPkcs, selected: false},
        MultiSelectItem{item: ObjectCapability::SignPss, selected: false},
        MultiSelectItem{item: ObjectCapability::DecryptPkcs, selected: false},
        MultiSelectItem{item: ObjectCapability::DecryptOaep, selected: false},
        MultiSelectItem{item: ObjectCapability::ExportableUnderWrap, selected: false}];
    get_selected_items(&mut capability_options)
}

fn get_ec_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<MultiSelectItem<ObjectCapability>> = vec![
        MultiSelectItem{item: ObjectCapability::SignEcdsa, selected: false},
        MultiSelectItem{item: ObjectCapability::DeriveEcdh, selected: false},
        MultiSelectItem{item: ObjectCapability::ExportableUnderWrap, selected: false}];
    get_selected_items(&mut capability_options)
}

fn get_ed_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<MultiSelectItem<ObjectCapability>> = vec![
        MultiSelectItem{item: ObjectCapability::SignEddsa, selected: false},
        MultiSelectItem{item: ObjectCapability::ExportableUnderWrap, selected: false}];
    get_selected_items(&mut capability_options)
}

fn asym_gen_key(session: Option<&Session>) -> Result<(), MgmError> {
    println!();
    let (key_id, label, domains) = get_common_properties();

    let mut key_algorithm:ObjectAlgorithm = ObjectAlgorithm::ANY;
    let mut capabilities:Vec<ObjectCapability> = Vec::new();

    match get_asym_keytype() {
        AsymKeyTypes::RSA => {
            let key_len = get_rsa_keylen();
            key_algorithm = match key_len {
                2048 => ObjectAlgorithm::Rsa2048,
                3072 => ObjectAlgorithm::Rsa3072,
                4096 => ObjectAlgorithm::Rsa4096,
                _ => unreachable!()
            };
            capabilities = get_rsakey_capabilities();
        }
        AsymKeyTypes::EC => {
            key_algorithm = get_ec_algo();
            capabilities = get_ec_capabilities();
        }
        AsymKeyTypes::ED => {
            key_algorithm = ObjectAlgorithm::Ed25519;
            capabilities = get_ed_capabilities();
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

    match session {
        None => {
            print!("  > yubihsm-shell -a generate_asymmetric-key");
            print!(" -i {}", key_id);
            print!(" -l \"{}\"", label);
            print!(" -d ");
            domains.iter().for_each(|domain| print!("{},", domain));
            print!(" -A {}", key_algorithm);
            print!(" -c ");
            capabilities.iter().for_each(|cap| print!("{:?},", cap));
            println!();
        },
        Some(session) => {
            if bool::from(get_boolean_answer("Execute? ")) {
                let key = session
                    .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)?;
                println!("  Generated asymmetric keypair with ID 0x{:04x} on the device", key.get_key_id());
            }
        }
    }
    Ok(())
}

fn print_import_key_cmd(key_id:u16, label:String, domains:Vec<ObjectDomain>, capabilities:Vec<ObjectCapability>) {
    print!("  > yubihsm-shell -a put_asymmetric-key");
    print!(" -i {}", key_id);
    print!(" -l \"{}\"", label);
    print!(" -d ");
    domains.iter().for_each(|domain| print!("{},", domain));
    print!(" -c ");
    capabilities.iter().for_each(|cap| print!("{:?},", cap));
    print!(" --in <PATH_TO_FILE>");
    println!();
}

fn asym_import_key(session:Option<&Session>) -> Result<(), MgmError>{
    println!();
    let (mut key_id, label, domains) = get_common_properties();

    let mut pem = pem::parse(read_file("Enter absolute path to PEM file: "));
    while pem.is_err() {
        println!("Unable to parse PEM content: {}", pem.err().unwrap());
        pem = pem::parse(read_file("Enter absolute path to PEM file: "));
    }
    let pem = pem.unwrap();
    let key_bytes = pem.contents();

    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            match key.id() {
                pkey::Id::RSA => {
                    println!("RSA key");
                    let private_rsa = key.rsa()?;
                    let p = private_rsa.p().ok_or(MgmError::Error(String::from("Failed to read p value")))?;
                    let q = private_rsa.q().ok_or(MgmError::Error(String::from("Failed to read q value")))?;

                    let key_algorithm: ObjectAlgorithm = match private_rsa.size() {
                        256 => ObjectAlgorithm::Rsa2048,
                        384 => ObjectAlgorithm::Rsa3072,
                        512 => ObjectAlgorithm::Rsa4096,
                        _ => {
                            println!("Unrecognized RSA algorithm");
                            return Err(MgmError::Error(format!("RSA key size {}", private_rsa.size())));
                        },
                    };

                    let capabilities = get_rsakey_capabilities();

                    match session {
                        None => print_import_key_cmd(key_id, label, domains, capabilities),
                        Some(session) => {
                            key_id = session
                                .import_rsa_key(key_id, &label, &*domains, &capabilities, key_algorithm, &p.to_vec(), &q.to_vec())?
                        }
                    }
                },
                pkey::Id::EC => {
                    let private_ec = key.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let nid = group.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
                    let key_algorithm = get_algo_from_nid(nid)?;
                    let capabilities = get_ec_capabilities();

                    match session {
                        None => print_import_key_cmd(key_id, label, domains, capabilities),
                        Some(session) => {
                            key_id = session
                                .import_ec_key(key_id, &label, &*domains, &capabilities, key_algorithm, &s.to_vec())?
                        }
                    }
                },
                pkey::Id::ED25519 => {
                    let private_ed= PKey::private_key_from_raw_bytes(key_bytes, openssl::pkey::Id::ED25519)?;
                    let k = private_ed.raw_private_key()?;
                    let capabilities = get_ed_capabilities();
                    match session {
                        None => print_import_key_cmd(key_id, label, domains, capabilities),
                        Some(session) => {
                            key_id = session
                                .import_ed_key(key_id, &label, &*domains, &capabilities, &k.to_vec())?
                        }
                    }
                },
                _ => println!("Unknown key type"),
            }
            println!("\n  Imported asymmetric keypair with ID 0x{:04x} on the device", key_id);
        }
        Err(err) => {
            let key_err = err;
            println!("Not a key. Trying to import as X509 certificate");
            match openssl::x509::X509::from_der(&key_bytes) {
                Ok(cert) => {
                    match session {
                        None => {
                            print!("  > yubihsm-shell -a put_opaque");
                            print!(" -i {}", key_id);
                            print!(" -l \"{}\"", label);
                            print!(" -d ");
                            domains.iter().for_each(|domain| print!("{},", domain));
                            print!(" -c none");
                            print!(" -A opaque-x509-certificate");
                            print!(" --in <PATH_TO_FILE>");
                            println!();
                        },
                        Some(session) => {
                            key_id = session
                                .import_cert(key_id, &label, &*domains, &cert.to_pem().unwrap())?;
                            println!("\n  Imported X509Certificate with ID 0x{:04x} on the device", key_id)
                        }
                    }
                },
                Err(cert_err) => {
                    println!("  {}", key_err);
                    println!("  {}", cert_err);
                    return Err(MgmError::Error(String::from("Error! Failed to find either private key or X509Certificate")));
                }
            }
        },
    };
    Ok(())
}

fn asym_list_keys(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("\n  > yubihsm-shell -a list-objects -t asymmetric-key"),
        Some(s) => {
            let key_handles:Vec<ObjectHandle> = get_filtered_objects(s, ObjectType::AsymmetricKey, true)?;
            println!("Found {} objects", key_handles.len());
            for object in key_handles {
                println!("  {}", s.get_object_info(object.object_id, object.object_type)?);
            }
        }
    }
    Ok(())
}

fn asym_get_key_properties(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("No session available"),
        Some(s) => {
            println!();
            if bool::from(get_boolean_answer("Is certificate?")) {
                print_object_properties(s, ObjectType::Opaque);
            } else {
                print_object_properties(s, ObjectType::AsymmetricKey);
            }
        }
    }
    Ok(())
}

fn asym_delete_key(session: Option<&Session>) -> Result<(), MgmError>{
    match session {
        None => println!("No session available"),
        Some(s) => {
            let keys = get_filtered_objects(s, ObjectType::AsymmetricKey, true)?;
            delete_objects(session, keys)?
        }
    }
    Ok(())
}

fn print_pem_string(pem_bytes:Vec<u8>) {
    println!();
    let pem_str = String::from_utf8(pem_bytes).unwrap();
    let chars:Vec<char> = pem_str.chars().collect();
    for c in chars {
        if c == '\n' {
            println!();
        } else {
            print!("{c}");
        }
    }
}

fn asym_get_public_key(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("Session not available"),
        Some(s) => {
            let keys = get_filtered_objects(s, ObjectType::AsymmetricKey, false)?;
            let mut pubkeys:Vec<(Vec<u8>, ObjectAlgorithm)> = Vec::new();
            match keys.len().cmp(&usize::try_from(1).unwrap()) {
                Ordering::Equal => pubkeys.push(s.get_pubkey(keys[0].object_id)?),
                Ordering::Greater => {
                    let mut key_options:Vec<MultiSelectItem<BasicDiscriptor>> = Vec::new();
                    for handle in keys {
                        key_options.push(MultiSelectItem{item: BasicDiscriptor::from(s.get_object_info(handle.object_id, handle.object_type)?), selected: false});
                    }
                    let selected_keys = get_selected_items(&mut key_options);
                    for desc in selected_keys {
                        pubkeys.push(s.get_pubkey(desc.object_id)?);
                    }
                },
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
                    let mut ec_pubkey_bytes:Vec<u8> = Vec::new();
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
        }
    }
    Ok(())
}


fn get_hashed_bytes(hash_algo:HashAlgorithm, input:&[u8]) -> Result<Vec<u8>, MgmError> {
    let digest:DigestBytes;
    match hash_algo {
        HashAlgorithm::SHA1 => digest = openssl::hash::hash(MessageDigest::sha1(), input)?,
        HashAlgorithm::SHA256 => digest = openssl::hash::hash(MessageDigest::sha256(), input)?,
        HashAlgorithm::SHA384 => digest = openssl::hash::hash(MessageDigest::sha384(), input)?,
        HashAlgorithm::SHA512 => digest = openssl::hash::hash(MessageDigest::sha512(), input)?,
    }
    Ok(digest.to_vec())
}

fn get_mgf1_algorithm(hash_algo:HashAlgorithm) -> ObjectAlgorithm {
    match hash_algo {
        HashAlgorithm::SHA1 => ObjectAlgorithm::Mgf1Sha1,
        HashAlgorithm::SHA256 => ObjectAlgorithm::Mgf1Sha256,
        HashAlgorithm::SHA384 => ObjectAlgorithm::Mgf1Sha384,
        HashAlgorithm::SHA512 => ObjectAlgorithm::Mgf1Sha512,
    }
}


fn get_operation_key(session:&Session, capability:ObjectCapability) -> Result<BasicDiscriptor, MgmError> {
    println!("\n  Choose signing or decryption key: ");
    let sign_capabilities: [ObjectCapability;1] = [capability];
    let key_handles = session.list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &sign_capabilities.to_vec())?;
    let mut key_options:Vec<(String, BasicDiscriptor)> = Vec::new();
    for handle in key_handles {
        let option = BasicDiscriptor::from(session.get_object_info(handle.object_id, handle.object_type)?);
        key_options.push((option.to_string(), option));
    }
    let chosen = get_menu_option(&key_options);
    Ok(chosen)
}



fn asym_sign(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("No session available"),
        Some(s) => {
            let mut input_str = "".to_string();

            match get_format(&vec![InputOutputFormat::STDIN, InputOutputFormat::BINARY]) {
                InputOutputFormat::STDIN => {
                    input_str = get_string("\nData to sign: ");
                },
                InputOutputFormat::BINARY => {
                    input_str = read_file("\nAbsolute path to file containing data to sign: ");
                },
                _ => unreachable!()
            }

            let signed_data = match get_sign_algo() {
                SignAlgorithm::PKCS1 => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let signing_key = get_operation_key(s, ObjectCapability::SignPkcs)?;
                    s.sign_pkcs1v1_5(signing_key.object_id, true, hashed_bytes.as_slice())?
                },
                SignAlgorithm::PSS => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let mgf1_algo = get_mgf1_algorithm(hash_algo);
                    let signing_key = get_operation_key(s, ObjectCapability::SignPss)?;
                    s.sign_pss(signing_key.object_id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?
                },
                SignAlgorithm::ECDSA => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let signing_key = get_operation_key(s, ObjectCapability::SignEcdsa)?;
                    s.sign_ecdsa(signing_key.object_id, hashed_bytes.as_slice())?
                },
                SignAlgorithm::EDDSA => {
                    let signing_key = get_operation_key(s, ObjectCapability::SignEddsa)?;
                    s.sign_eddsa(signing_key.object_id, input_str.as_bytes())?
                },
            };

            write_file(signed_data, "data.sig".to_string())?;
        }
    }
    Ok(())
}

fn asym_decrypt(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("No session available"),
        Some(s) => {
            let input_bytes = read_file_bytes("\nAbsolute path to file containing encrypted data: ");

            let decrypted_data = match get_decrypt_algo() {
                DecryptAlgorithm::PKCS1 => {
                    let decryption_key = get_operation_key(s, ObjectCapability::DecryptPkcs)?;
                    s.decrypt_pkcs1v1_5(decryption_key.object_id, input_bytes.as_slice())?
                },
                DecryptAlgorithm::OAEP => {
                    println!("\n  Choose OAEP decryption algorithm:");
                    let hash_algos: [(String, HashAlgorithm);4] = [
                        ("RSA OAEP SHA1".to_string(), HashAlgorithm::SHA1),
                        ("RSA OAEP SHA256".to_string(), HashAlgorithm::SHA256),
                        ("RSA OAEP SHA384".to_string(), HashAlgorithm::SHA384),
                        ("RSA OAEP SHA512".to_string(), HashAlgorithm::SHA512)];
                    let hash_algo = get_menu_option(&hash_algos.to_vec());
                    let label = get_hashed_bytes(hash_algo, input_bytes.as_slice())?;
                    let mgf1_algo = get_mgf1_algorithm(hash_algo);
                    let decryption_key = get_operation_key(s, ObjectCapability::DecryptOaep)?;
                    s.decrypt_oaep(decryption_key.object_id, input_bytes.as_slice(), label.as_slice(), mgf1_algo)?
                },
            };

            write_file(decrypted_data, "data.dec".to_string())?;
        }
    }
    Ok(())
}

fn asym_derive_ecdh(session: Option<&Session>) -> Result<(), MgmError> {
    match  session {
        None => println!("No session open"),
        Some(s) => {

            let pubkey = openssl::ec::EcKey::public_key_from_pem(read_file("Enter absolute path to EC public key PEM file: ").as_bytes())?;
            let ec_point_ref = pubkey.public_key();
            let ec_group_ref = pubkey.group();
            let mut ctx = BigNumContext::new()?;
            let ext_key = ec_point_ref.to_bytes(ec_group_ref, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
            let nid = ec_group_ref.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
            let ext_key_algo = get_algo_from_nid(nid)?;

            let hsm_key = get_operation_key(s, ObjectCapability::DeriveEcdh)?;

            if hsm_key.object_algorithm != ext_key_algo {
                return Err(MgmError::Error("External EC public key has a different algorithm the the YubiHSM key".to_string()));
            }

            let ecdh = s.derive_ecdh(hsm_key.object_id, ext_key.as_slice())?;
            for b in ecdh {
                print!("{b:02x}");
            }
            println!();
        }
    };
    Ok(())
}
