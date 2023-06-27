use std::fs::File;
use std::io::{BufReader, stdin, stdout, Write};
use std::iter;
use std::ptr::write;
use crate::util::{get_integer, get_string, get_domains, get_menu_option, get_multiselect_options, get_boolean_answer, get_selected_items, delete_objects, read_file}; // 0.17.1
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;


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


pub fn exec_asym_command(session: Option<&Session>) {
    let cmd = get_asym_command();
    match cmd {
        AsymCommands::ListKeys => asym_list_keys(session),
        AsymCommands::GenerateKey => asym_gen_key(session),
        AsymCommands::DeleteKey => asym_delete_key(session.unwrap()),
        AsymCommands::ImportKey => asym_import_key(session),
        _ => {}
    }
}

pub fn get_asym_command() -> AsymCommands {
    writeln!(stdout());
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
    writeln!(stdout(), "\n  Choose key type:");
    let mut types: [(String, AsymKeyTypes);3] = [
        (String::from("RSA"), AsymKeyTypes::RSA),
        (String::from("EC"), AsymKeyTypes::EC),
        (String::from("ED"), AsymKeyTypes::ED)];
    get_menu_option(&types)
}

pub fn get_ec_algo() -> ObjectAlgorithm {
    writeln!(stdout(), "\n  Choose EC Curve:");
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

fn asym_gen_key(session: Option<&Session>) {
    writeln!(stdout());
    let label = get_string("Enter key label [Default empty]: ", "");
    let mut key_id: u16 = get_integer("Enter key ID [Default 0]: ", true, 0);
    let domains = get_domains("Enter domain(s), multiple domains are separated by ',' [1-16]: ");

    let mut key_algorithm:ObjectAlgorithm = ObjectAlgorithm::RsaPkcs1Sha1;
    let mut capability_options: Vec<(ObjectCapability, bool)> = Vec::new();
    let mut capabilities:Vec<ObjectCapability> = Vec::new();

    let key_type = get_asym_keytype();
    match key_type {
        AsymKeyTypes::RSA => {
            let key_len = get_rsa_keylen();
            key_algorithm = match key_len {
                2048 => ObjectAlgorithm::Rsa2048,
                3072 => ObjectAlgorithm::Rsa3072,
                4096 => ObjectAlgorithm::Rsa4096,
                _ => ObjectAlgorithm::Rsa2048
            };

            capability_options.push((ObjectCapability::SignPkcs, false));
            capability_options.push((ObjectCapability::SignPss, false));
            capability_options.push((ObjectCapability::DecryptPkcs, false));
            capability_options.push((ObjectCapability::DecryptOaep, false));
            capability_options.push((ObjectCapability::ExportableUnderWrap, false));
        }
        AsymKeyTypes::EC => {
            key_algorithm = get_ec_algo();
            capability_options.push((ObjectCapability::SignEcdsa, false));
            capability_options.push((ObjectCapability::DeriveEcdh, false));
            capability_options.push((ObjectCapability::ExportableUnderWrap, false));
        }
        AsymKeyTypes::ED => {
            key_algorithm = ObjectAlgorithm::Ed25519;
            capability_options.push((ObjectCapability::SignEddsa, false));
            capability_options.push((ObjectCapability::ExportableUnderWrap, false));

        }
    };
    get_multiselect_options(&mut capability_options);
    capabilities = get_selected_items(&capability_options);

    writeln!(stdout(), "\n  Generatin RSA key with:");
    writeln!(stdout(), "    Key algorithm: {}", key_algorithm);
    writeln!(stdout(), "    Label: {}", label);
    writeln!(stdout(), "    Key ID: {}", key_id);
    write!(stdout(), "    Domains: ");
    domains.iter().for_each(|domain| write!(stdout(), "{}, ", domain).unwrap());
    writeln!(stdout());
    write!(stdout(), "    Capabilities: ");
    capabilities.iter().for_each(|cap| write!(stdout(), "{:?}, ", cap).unwrap());
    writeln!(stdout(), "\n\n");


    match session {
        None => {
            write!(stdout(), "  > yubihsm-shell -a generate_asymmetric-key");
            write!(stdout(), " -i {}", key_id);
            write!(stdout(), " -l \"{}\"", label);
            write!(stdout(), " -d ");
            domains.iter().for_each(|domain| write!(stdout(), "{},", domain).unwrap());
            write!(stdout(), " -A {}", key_algorithm);
            write!(stdout(), " -c ");
            capabilities.iter().for_each(|cap| write!(stdout(), "{:?},", cap).unwrap());
            writeln!(stdout());

        },
        Some(session) => {
            if bool::from(get_boolean_answer("Execute? ")) {
                let key = session
                    .generate_asymmetric_key_with_keyid(key_id, &label, &capabilities, &*domains, key_algorithm)
                    .unwrap_or_else(|err| {
                        writeln!(stdout(), "Unable to generate keypair: {}", err);
                        std::process::exit(1);
                    });
                let key_id = key.get_key_id();
                writeln!(stdout(), "  Generated asymmetric keypair with ID 0x{:04x} on the device", key_id);
            }
        }
    }
}

fn print_descriptor(desc:&ObjectDescriptor) {
    write!(stdout(), "id: 0x{:04x?}\t", desc.id);
    write!(stdout(), "label: {:40}\t", desc.label);
    write!(stdout(), "algo: {:10}\t", desc.algorithm);
    write!(stdout(), "seq: {:2}\t", desc.sequence);
    write!(stdout(), "origin: {:10?}\t", desc.origin);
    //write!(stdout(), "domains: ");
    let mut dom_str = String::new().to_owned();
    //desc.domains.iter().for_each(|domain| write!(stdout(), "{},", domain).unwrap());
    desc.domains.iter().for_each(|domain| dom_str.push_str(format!("{},", domain).as_str()));
    //desc.domains.iter().for_each(|domain| dom_str.push_str(&*domain.to_string()+","));
    write!(stdout(), "domains: {:20}\t", dom_str);
    write!(stdout(), "\tcapabilities: ");
    desc.capabilities.iter().for_each(|cap| write!(stdout(), "{:?}, ", cap).unwrap());
    writeln!(stdout());
}

fn get_objects_list(session:&Session, id:u16, label:String) -> Vec<ObjectHandle> {
    let mut found_objects:Vec<ObjectHandle> = session.list_objects_with_filter(id, ObjectType::AsymmetricKey, &label, ObjectAlgorithm::ANY).unwrap();
    found_objects.extend(session.list_objects_with_filter(id, ObjectType::Opaque, &label, ObjectAlgorithm::OpaqueX509Certificate).unwrap());
    found_objects
}

fn get_filtered_objects(session:&Session) -> Vec<ObjectHandle> {
    writeln!(stdout(), "\n  List key by:");
    let mut criterias: [(String, IdLabelOption);3] = [
        (String::from("All"), IdLabelOption::ALL),
        (String::from("Filter by object ID"), IdLabelOption::ByID),
        (String::from("Filter by object Label"), IdLabelOption::ByLabel)];
    let criteria = get_menu_option(&criterias);
    writeln!(stdout());

    let mut key_handles:Vec<ObjectHandle> = Vec::new();

    match criteria {
        IdLabelOption::ALL => key_handles = get_objects_list(session, 0, String::from("")),
        IdLabelOption::ByID => {
            let mut key_id: u16 = get_integer("Enter key ID [Default 0]: ", true, 0);
            key_handles = get_objects_list(session, key_id, String::from(""));
        },
        IdLabelOption::ByLabel => {
            let label = get_string("Enter key label [Default empty]: ", "");
            key_handles = get_objects_list(session, 0, label);
        },
    }
    key_handles
}

fn asym_list_keys(session: Option<&Session>) {
    match session {
        None => writeln!(stdout(), "\n  > yubihsm-shell -a list-objects -t asymmetric-key").unwrap(),
        Some(session) => {
            let mut key_handles:Vec<ObjectHandle> = get_filtered_objects(session);
            writeln!(stdout(), "Found {} objects", key_handles.len());
            for h in key_handles {
                let desc = session.get_object_info(h.object_id, h.object_type).unwrap();
                print_descriptor(&desc);
            }
        }
    }
}

fn asym_delete_key(session: &Session) {
    let mut keys = get_filtered_objects(session);
    delete_objects(session, keys);
}

fn asym_import_key(session:Option<&Session>) {
    writeln!(stdout());
    let label = get_string("Enter key label [Default empty]: ", "");
    let mut key_id: u16 = get_integer("Enter key ID [Default 0]: ", true, 0);
    let domains = get_domains("Enter domain(s), multiple domains are separated by ',' [1-16]: ");

    let mut capability_options: Vec<(ObjectCapability, bool)> = Vec::new();
    capability_options.push((ObjectCapability::SignPkcs, false));
    capability_options.push((ObjectCapability::SignPss, false));
    capability_options.push((ObjectCapability::DecryptPkcs, false));
    capability_options.push((ObjectCapability::DecryptOaep, false));
    capability_options.push((ObjectCapability::ExportableUnderWrap, false));
    get_multiselect_options(&mut capability_options);
    let mut capabilities:Vec<ObjectCapability> = get_selected_items(&capability_options);



    let key_str = read_file();
    let pem = pem::parse(key_str).unwrap();
    writeln!(stdout(), "pem.tag: {}", pem.tag());
    let headers = pem.headers();
    for h in headers.iter() {
        writeln!(stdout(), "header:  {}: {}", h.0, h.1);
    }
    let key_bytes = pem.contents();

    write!(stdout(), "{} : ", key_bytes.len());
    for u in key_bytes {
        write!(stdout(), "{:x}", u);
    }
    writeln!(stdout());

    writeln!(stdout(), "Parsing with openssl:");
    match openssl::pkey::PKey::private_key_from_der(&key_bytes) {
        Ok(key) => {
            writeln!(stdout(), "Found private key");
            match key.id() {
                openssl::pkey::Id::RSA => {
                    writeln!(stdout(), "RSA key");
                    let private_rsa = key.rsa().unwrap();
                    let p = private_rsa.p().unwrap();
                    let q = private_rsa.q().unwrap();
                    writeln!(stdout(), "size: {}", private_rsa.size());
                    writeln!(stdout(), "p: {}", p);
                    writeln!(stdout(), "q: {}", q);

                    let key_algorithm: ObjectAlgorithm = match private_rsa.size() {
                        256 => ObjectAlgorithm::Rsa2048,
                        384 => ObjectAlgorithm::Rsa3072,
                        512 => ObjectAlgorithm::Rsa4096,
                        _ => {
                            writeln!(stdout(), "Unrecognized algo");
                            return;
                        },
                    };

                    let s = session.unwrap();
                    key_id = s
                        .import_rsa_key(key_id, &label, &*domains, &capabilities, key_algorithm, &p.to_vec(), &q.to_vec())
                        .unwrap_or_else(|err| {
                            writeln!(stdout(), "Unable to import keypair: {}", err);
                            std::process::exit(1);
                        });
                    writeln!(stdout(), "  Imported asymmetric keypair with ID 0x{:04x} on the device", key_id)
                },
                openssl::pkey::Id::EC => writeln!(stdout(), "EC key"),
                _ => writeln!(stdout(), "Unknown key type"),
            }
        }
        Err(err) => writeln!(stdout(), "error: {}", err),
    }.expect("TODO: panic message");

    /*
        let mut reader = BufReader::new(key_bytes);
        let res = rustls_pemfile::read_one(&mut reader);
        match res {
            Ok(None) => writeln!(stdout(), "No pem file"),
            Err(e) => writeln!(stdout(), "error reading: {}", e),
            Ok(Some(iter)) => writeln!(stdout(), "Some iter returned"),
        };

        for item in iter::from_fn(|| rustls_pemfile::read_one(&mut reader).transpose()) {
            writeln!(stdout(), "inside for");
            match item.unwrap() {
                rustls_pemfile::Item::X509Certificate(cert) => {
                    writeln!(stdout(), "certificate {:?}", cert);
                },
                rustls_pemfile::Item::RSAKey(key) => {
                    writeln!(stdout(), "rsa pkcs1 key {:?}", key);
                },
                _ => continue,
            }
        }
         */

    /*
        let mut file_path = get_string("Enter absolute path to PEM file: ", "");
        while file_path == "" {
            file_path = get_string("Enter absolute path to PEM file: ", "");
        }
        let file = File::open(&file_path).unwrap();
        let mut reader = BufReader::new(file);
        match rustls_pemfile::pkcs8_private_keys(&mut reader) {
            Err(err) => writeln!(stdout(), "error: {}", err),
            Ok(keys) => {
                match keys.len() {
                    0 => writeln!(stdout(), "No key was found in file"),
                    1 => {
                        writeln!(stdout(), "1 key is read")
                    },
                    _ => writeln!(stdout(), "More than one PKCS8-encoded private key found in file"),
                }
            }
        }.expect("TODO: panic message");
    */
}

