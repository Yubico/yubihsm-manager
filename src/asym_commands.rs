use openssl::nid::Nid;
use openssl::pkey::PKey;
use crate::util::{get_integer, get_string, get_domains, get_menu_option, get_multiselect_options, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use util::get_common_properties;


#[derive(Debug, Clone, Copy)]
pub enum AsymCommands {
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    DeleteKey,
    DeleteCert,
    ImportKey,
    PerformSignature,
    PerformRsaDecryption,
    DeriveEcdh,
    GenerateJavaKey,
    DeleteJavaKey,
}

#[derive(Debug, Clone, Copy)]
pub enum AsymKeyTypes {
    RSA,
    EC,
    ED,
}

#[derive(Debug, Clone, Copy)]
pub enum IdLabelOption {
    ALL,
    ByID,
    ByLabel,
}


pub fn exec_asym_command(session: Option<&Session>) -> Result<(), yubihsmrs::error::Error> {
    let cmd = get_asym_command();
    match cmd {
        AsymCommands::ListKeys => asym_list_keys(session),
        AsymCommands::GenerateKey => asym_gen_key(session),
        AsymCommands::DeleteKey => asym_delete_key(session),
        AsymCommands::ImportKey => asym_import_key(session),
        _ => unreachable!()
    }
}

pub fn get_asym_command() -> AsymCommands {
    println!();
    let mut commands: [(String, AsymCommands);9] = [
        (String::from("List keys"), AsymCommands::ListKeys),
        (String::from("Generate key"), AsymCommands::GenerateKey),
        (String::from("Import key"), AsymCommands::ImportKey),
        (String::from("Delete key"), AsymCommands::DeleteKey),
        (String::from("Perform signature"), AsymCommands::PerformSignature),
        (String::from("Perform RSA decryption"), AsymCommands::PerformRsaDecryption),
        (String::from("Derive ECDH"), AsymCommands::DeriveEcdh),
        (String::from("Generate JAVA key (Usable with SunPKCS11 provider)"), AsymCommands::GenerateJavaKey),
        (String::from("Delete JAVA key (Deletes an asymmetric key and the X509Certificate with the same ID)"), AsymCommands::DeleteJavaKey)];
    get_menu_option(&commands)
}

pub fn get_asym_keytype() -> AsymKeyTypes {
    println!("\n  Choose key type:");
    let mut types: [(String, AsymKeyTypes);3] = [
        (String::from("RSA"), AsymKeyTypes::RSA),
        (String::from("EC"), AsymKeyTypes::EC),
        (String::from("ED"), AsymKeyTypes::ED)];
    get_menu_option(&types)
}

pub fn get_ec_algo() -> ObjectAlgorithm {
    println!("\n  Choose EC Curve:");
    let mut curves: [(String, ObjectAlgorithm);8] = [
        (String::from("secp224r1"), ObjectAlgorithm::EcP224),
        (String::from("secp256r1"), ObjectAlgorithm::EcP256),
        (String::from("secp384r1"), ObjectAlgorithm::EcP384),
        (String::from("secp521r1"), ObjectAlgorithm::EcP521),
        (String::from("secp256k1"), ObjectAlgorithm::EcK256),
        (String::from("brainpool256r1"), ObjectAlgorithm::EcBp256),
        (String::from("brainpool384r1"), ObjectAlgorithm::EcBp384),
        (String::from("brainpool512r1"), ObjectAlgorithm::EcBp512)];
    get_menu_option(&curves)
}

fn get_rsa_keylen() -> u32 {
    let accepted_len = vec![2048, 3072, 4096];
    let mut key_len:u32 = 0;
    while !accepted_len.contains(&key_len){
        key_len = get_integer("Enter key length [2048, 3072, 4096] [defualt 2048]: ", true, 2048);
    }
    key_len
}

fn get_rsakey_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<(ObjectCapability, bool)> = Vec::new();
    capability_options.push((ObjectCapability::SignPkcs, false));
    capability_options.push((ObjectCapability::SignPss, false));
    capability_options.push((ObjectCapability::DecryptPkcs, false));
    capability_options.push((ObjectCapability::DecryptOaep, false));
    capability_options.push((ObjectCapability::ExportableUnderWrap, false));
    get_multiselect_options(&mut capability_options);
    get_selected_items(&capability_options)
}

fn get_ec_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<(ObjectCapability, bool)> = Vec::new();
    capability_options.push((ObjectCapability::SignEcdsa, false));
    capability_options.push((ObjectCapability::DeriveEcdh, false));
    capability_options.push((ObjectCapability::ExportableUnderWrap, false));
    get_multiselect_options(&mut capability_options);
    get_selected_items(&capability_options)
}

fn get_ed_capabilities() -> Vec<ObjectCapability> {
    let mut capability_options: Vec<(ObjectCapability, bool)> = Vec::new();
    capability_options.push((ObjectCapability::SignEddsa, false));
    capability_options.push((ObjectCapability::ExportableUnderWrap, false));
    get_multiselect_options(&mut capability_options);
    get_selected_items(&capability_options)
}

fn asym_gen_key(session: Option<&Session>) -> Result<(), yubihsmrs::error::Error> {
    println!();
    let (mut key_id, label, domains) = get_common_properties();

    let mut key_algorithm:ObjectAlgorithm = ObjectAlgorithm::RsaPkcs1Sha1;
    let mut capabilities:Vec<ObjectCapability> = Vec::new();

    let key_type = get_asym_keytype();
    match key_type {
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

    println!("\n  Generating RSA key with:");
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

fn print_descriptor(desc:&ObjectDescriptor) {
    print!("id: 0x{:04x?}\t", desc.id);
    print!("label: {:40}\t", desc.label);
    print!("algo: {:10}\t", desc.algorithm);
    print!("seq: {:2}\t", desc.sequence);
    print!("origin: {:10?}\t", desc.origin);
    //print!(, "domains: ");
    let mut dom_str = String::new().to_owned();
    //desc.domains.iter().for_each(|domain| print!(, "{},", domain).unwrap());
    desc.domains.iter().for_each(|domain| dom_str.push_str(format!("{},", domain).as_str()));
    //desc.domains.iter().for_each(|domain| dom_str.push_str(&*domain.to_string()+","));
    print!("domains: {:20}\t", dom_str);
    print!("\tcapabilities: ");
    desc.capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!();
}

fn get_objects_list(session:&Session, id:u16, label:String) -> Result<Vec<ObjectHandle>, yubihsmrs::error::Error> {
    let mut found_objects = session.list_objects_with_filter(id, ObjectType::AsymmetricKey, &label, ObjectAlgorithm::ANY)?;
    found_objects.extend(session.list_objects_with_filter(id, ObjectType::Opaque, &label, ObjectAlgorithm::OpaqueX509Certificate)?);
    Ok(found_objects)
}

fn get_filtered_objects(session: Option<&Session>) -> Result<Vec<ObjectHandle>,yubihsmrs::error::Error> {
    let mut key_handles:Vec<ObjectHandle> = Vec::new();
    match session {
        None => {},
        Some(session) => {
            println!("\n  List key by:");
            let mut criterias: [(String, IdLabelOption);3] = [
                (String::from("All"), IdLabelOption::ALL),
                (String::from("Filter by object ID"), IdLabelOption::ByID),
                (String::from("Filter by object Label"), IdLabelOption::ByLabel)];
            let criteria = get_menu_option(&criterias);
            println!();

            match criteria {
                IdLabelOption::ALL => key_handles = get_objects_list(session, 0, String::from(""))?,
                IdLabelOption::ByID => {
                    let mut key_id: u16 = get_integer("Enter key ID [Default 0]: ", true, 0);
                    key_handles = get_objects_list(session, key_id, String::from(""))?;
                },
                IdLabelOption::ByLabel => {
                    let label = get_string("Enter key label [Default empty]: ", "");
                    key_handles = get_objects_list(session, 0, label)?;
                },
            }
        }
    }
    Ok(key_handles)
}

fn asym_list_keys(session: Option<&Session>) -> Result<(), yubihsmrs::error::Error> {
    match session {
        None => println!("\n  > yubihsm-shell -a list-objects -t asymmetric-key"),
        Some(s) => {
            let mut key_handles:Vec<ObjectHandle> = get_filtered_objects(session)?;
            println!("Found {} objects", key_handles.len());
            for h in key_handles {
                let desc = s.get_object_info(h.object_id, h.object_type).unwrap();
                print_descriptor(&desc);
            }
        }
    }
    Ok(())
}

fn asym_delete_key(session: Option<&Session>) -> Result<(), yubihsmrs::error::Error>{
    let mut keys = get_filtered_objects(session)?;
    delete_objects(session, keys)
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

fn asym_import_key(session:Option<&Session>) -> Result<(), yubihsmrs::error::Error>{
    println!();
    let (mut key_id, label, domains) = get_common_properties();

    let key_str = read_file();
    let pem = pem::parse(key_str).unwrap_or_else(|err| {
        println!("Unable to parse PEM content: {}", err);
        std::process::exit(1);
    });
    let key_bytes = pem.contents();

    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            match key.id() {
                openssl::pkey::Id::RSA => {
                    println!("RSA key");
                    let private_rsa = key.rsa().unwrap();
                    let p = private_rsa.p().unwrap();
                    let q = private_rsa.q().unwrap();

                    let key_algorithm: ObjectAlgorithm = match private_rsa.size() {
                        256 => ObjectAlgorithm::Rsa2048,
                        384 => ObjectAlgorithm::Rsa3072,
                        512 => ObjectAlgorithm::Rsa4096,
                        _ => {
                            println!("Unrecognized algo");
                            return Err(yubihsmrs::error::Error::InvalidParameter(String::from("KeyAlgorithm")));
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
                    let private_ec = key.ec_key().unwrap();
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let nid = group.curve_name().unwrap();
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
                            println!("Unrecognized algo");
                            return Err(yubihsmrs::error::Error::InvalidParameter(String::from("KeyAlgorithm")));
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
                    let private_ed= PKey::private_key_from_raw_bytes(key_bytes, openssl::pkey::Id::ED25519).unwrap();
                    let k = private_ed.raw_private_key().unwrap();
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
            println!("Not a key");
            match openssl::x509::X509::from_der(&key_bytes) {
                Ok(cert) => {
                    println!("Found cert");
                    println!("subjectname: {:?}", cert.subject_name());
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
                    println!("Error! Failed to find either private key or X509Certificate");
                    println!("  {}", key_err);
                    println!("  {}", cert_err);
                }
            }
        },
    };
    Ok(())
}

