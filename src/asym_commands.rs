use std::io::{stdout, Write};
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use crate::util::{get_string, get_menu_option, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{BasicDiscriptor, get_common_properties, get_integer_or_default, get_string_or_default, MultiSelectItem, print_object_properties, write_file};


#[derive(Debug, Clone, Copy)]
enum AsymCommands {
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
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
enum HashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug, Clone, Copy)]
enum IdLabelOption {
    ALL,
    ByID,
    ByLabel,
}

#[derive(Debug, Clone, Copy)]
enum InputFormat {
    STDIN,
    BINARY,
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
        AsymCommands::PerformSignature => asym_sign(session),
        AsymCommands::Exit => std::process::exit(0),
        _ => unreachable!()
    }
}

fn get_asym_command() -> AsymCommands {
    println!();
    let commands: [(String, AsymCommands);10] = [
        ("List keys".to_string(), AsymCommands::ListKeys),
        ("Get key properties".to_string(), AsymCommands::GetKeyProperties),
        ("Generate key".to_string(), AsymCommands::GenerateKey),
        ("Import key".to_string(), AsymCommands::ImportKey),
        ("Delete key".to_string(), AsymCommands::DeleteKey),
        ("Perform signature".to_string(), AsymCommands::PerformSignature),
        ("Perform RSA decryption".to_string(), AsymCommands::PerformRsaDecryption),
        ("Derive ECDH".to_string(), AsymCommands::DeriveEcdh),
        ("Manage JAVA keys (Usable with SunPKCS11 provider)".to_string(), AsymCommands::ManageJavaKeys),
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
    println!("\n  Sign with:");
    let algos: [(String, SignAlgorithm);4] = [
        ("RSA-PKCS#1v1.5".to_string(), SignAlgorithm::PKCS1),
        ("RSA-PSS".to_string(), SignAlgorithm::PSS),
        ("ECDSA".to_string(), SignAlgorithm::ECDSA),
        ("EDDSA".to_string(), SignAlgorithm::EDDSA),];
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

fn get_input_format() -> InputFormat {
    println!("\n  Choose input_format:");
    let format: [(String, InputFormat);2] = [
        ("Stdin".to_string(), InputFormat::STDIN),
        ("Binary file".to_string(), InputFormat::BINARY)];
    get_menu_option(&format.to_vec())
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
                openssl::pkey::Id::RSA => {
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
                openssl::pkey::Id::EC => {
                    let private_ec = key.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let nid = group.curve_name().ok_or(MgmError::Error(String::from("Failed to read EC curve name")))?;
                    let key_algorithm: ObjectAlgorithm = match nid {
                        Nid::X9_62_PRIME256V1 => ObjectAlgorithm::EcP256,
                        Nid::SECP256K1 => ObjectAlgorithm::EcK256,
                        Nid::SECP384R1 => ObjectAlgorithm::EcP384,
                        Nid::SECP521R1 => ObjectAlgorithm::EcP521,
                        Nid::SECP224R1 => ObjectAlgorithm::EcP224,
                        Nid::BRAINPOOL_P256R1 => ObjectAlgorithm::EcBp256,
                        Nid::BRAINPOOL_P384R1 => ObjectAlgorithm::EcBp384,
                        Nid::BRAINPOOL_P512R1 => ObjectAlgorithm::EcBp512,
                        _ => {
                            println!("Unrecognized EC curve");
                            return Err(MgmError::InvalidInput(format!("EC curve {:?}", nid)));
                        },
                    };
                    let capabilities = get_ec_capabilities();

                    match session {
                        None => print_import_key_cmd(key_id, label, domains, capabilities),
                        Some(session) => {
                            key_id = session
                                .import_ec_key(key_id, &label, &*domains, &capabilities, key_algorithm, &s.to_vec())?
                        }
                    }
                },
                openssl::pkey::Id::ED25519 => {
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

fn get_objects_list(session:&Session, id:u16, label:String) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut found_objects = session.list_objects_with_filter(id, ObjectType::AsymmetricKey, &label, ObjectAlgorithm::ANY, &Vec::new())?;
    found_objects.extend(session.list_objects_with_filter(id, ObjectType::Opaque, &label, ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    Ok(found_objects)
}

fn get_filtered_objects(session: Option<&Session>) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut key_handles:Vec<ObjectHandle> = Vec::new();
    match session {
        None => {},
        Some(session) => {
            println!("\n  List key by:");
            let criterias: [(String, IdLabelOption);3] = [
                (String::from("All"), IdLabelOption::ALL),
                (String::from("Filter by object ID"), IdLabelOption::ByID),
                (String::from("Filter by object Label"), IdLabelOption::ByLabel)];
            let criteria = get_menu_option(&criterias.to_vec());
            println!();

            match criteria {
                IdLabelOption::ALL => key_handles = get_objects_list(session, 0, String::from(""))?,
                IdLabelOption::ByID => {
                    let key_id: u16 = get_integer_or_default("Enter key ID [Default 0]: ", 0);
                    key_handles = get_objects_list(session, key_id, String::from(""))?;
                },
                IdLabelOption::ByLabel => {
                    let label = get_string_or_default("Enter key label [Default empty]: ", "");
                    key_handles = get_objects_list(session, 0, label)?;
                },
            }
        }
    }
    Ok(key_handles)
}

fn asym_list_keys(session: Option<&Session>) -> Result<(), MgmError> {
    match session {
        None => println!("\n  > yubihsm-shell -a list-objects -t asymmetric-key"),
        Some(s) => {
            let key_handles:Vec<ObjectHandle> = get_filtered_objects(session)?;
            println!("Found {} objects", key_handles.len());
            for object in key_handles {
                println!("  {}", s.get_object_info(object.object_id, object.object_type)?);
            }
        }
    }
    Ok(())
}

fn asym_get_key_properties(session: Option<&Session>) -> Result<(), MgmError>{
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
    let keys = get_filtered_objects(session)?;
    delete_objects(session, keys)
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


fn get_signdec_key(session:&Session, capability:ObjectCapability) -> Result<BasicDiscriptor, MgmError> {
    println!("\n  Choose signing or decryption key: ");
    let sign_capabilities: [ObjectCapability;1] = [capability];
    let key_handles = session.list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &sign_capabilities.to_vec())?;
    let mut key_options:Vec<(String, BasicDiscriptor)> = Vec::new();
    for handle in key_handles {
        let key = session.get_object_info(handle.object_id, handle.object_type)?;
        let option = BasicDiscriptor { object_id: key.id, object_label: key.label };
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

            match get_input_format() {
                InputFormat::STDIN => {
                    input_str = get_string("\nData to sign: ");
                },
                InputFormat::BINARY => {
                    input_str = read_file("\nAbsolute path to file containing data to sign: ");
                }
            }

            let signed_data:Vec<u8>;
            match get_sign_algo() {
                SignAlgorithm::PKCS1 => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let signing_key = get_signdec_key(s, ObjectCapability::SignPkcs)?;
                    signed_data = s.sign_pkcs1v1_5(signing_key.object_id, true, hashed_bytes.as_slice())?;
                },
                SignAlgorithm::PSS => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let mgf1_algo = get_mgf1_algorithm(hash_algo);
                    let signing_key = get_signdec_key(s, ObjectCapability::SignPss)?;
                    signed_data = s.sign_pss(signing_key.object_id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?;
                },
                SignAlgorithm::ECDSA => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let signing_key = get_signdec_key(s, ObjectCapability::SignEcdsa)?;
                    signed_data = s.sign_ecdsa(signing_key.object_id, hashed_bytes.as_slice())?;
                },
                SignAlgorithm::EDDSA => {
                    let hash_algo = get_hash_algorithm();
                    let hashed_bytes = get_hashed_bytes(hash_algo, input_str.as_bytes())?;
                    let signing_key = get_signdec_key(s, ObjectCapability::SignEddsa)?;
                    signed_data = s.sign_eddsa(signing_key.object_id, hashed_bytes.as_slice())?;
                },
            }

            write_file(signed_data, "data.sig".to_string())?;
        }
    }
    Ok(())
}
