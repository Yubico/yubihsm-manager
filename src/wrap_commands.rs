use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, stdout, Write};
use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{delete_objects, get_boolean_answer, get_common_properties, get_filtered_objects, get_integer, get_integer_or_default, get_menu_option, get_string, print_object_properties, select_object_capabilities};
use regex::Regex;

#[derive(Debug, Clone, Copy)]
enum WrapCommand {
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
    DeleteKey,
    PerformBackup,
    PerformRestore,
    Exit,
}

#[derive(Debug, Clone, Copy)]
enum WrapImportKeyCommand {
    UserGenerated,
    DeviceGenerated,
    ImportFromShares,
    ReturnToMenu,
    Exit,
}

const ACCEPTED_WRAP_KEY_LEN: [u32;3] = [128, 192, 256];

lazy_static! {
    static ref SHARE_RE_256: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap();
    static ref SHARE_RE_192: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap();
    static ref SHARE_RE_128: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap();
}

pub fn exec_wrap_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        stdout().flush().unwrap();
        let cmd = get_wrap_command(session, current_authkey)?;
        match cmd {
            WrapCommand::ListKeys => wrap_list_keys(session)?,
            WrapCommand::GetKeyProperties => wrap_get_key_properties(session)?,
            WrapCommand::GenerateKey => wrap_gen_key(session, current_authkey)?,
            WrapCommand::ImportKey => wrap_import_key(session, current_authkey)?,
            WrapCommand::DeleteKey => wrap_delete_key(session)?,
            WrapCommand::PerformBackup => backup_device(session)?,
            WrapCommand::PerformRestore => restore_device(session)?,
            WrapCommand::Exit => std::process::exit(0),
        }
    }
}

fn get_wrap_command(session: &Session, current_authkey: u16) -> Result<WrapCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands: Vec<(String, WrapCommand)> = Vec::new();
    commands.push(("List keys".to_string(), WrapCommand::ListKeys));
    commands.push(("Get key properties".to_string(), WrapCommand::GetKeyProperties));
    if capabilities.contains(&ObjectCapability::GenerateWrapKey) {
        commands.push(("Generate key".to_string(), WrapCommand::GenerateKey));
    }
    if capabilities.contains(&ObjectCapability::PutWrapKey) {
        commands.push(("Import key".to_string(), WrapCommand::ImportKey));
    }
    if capabilities.contains(&ObjectCapability::DeleteWrapKey) {
        commands.push(("Delete key".to_string(), WrapCommand::DeleteKey));
    }
    if capabilities.contains(&ObjectCapability::ExportWrapped) {
        commands.push(("Perform backup".to_string(), WrapCommand::PerformBackup));
    }
    if capabilities.contains(&ObjectCapability::ImportWrapped) {
        commands.push(("Perform restore".to_string(), WrapCommand::PerformRestore));
    }
    commands.push(("Exit".to_string(), WrapCommand::Exit));
    println!();
    Ok(get_menu_option(&commands))
}

fn wrap_list_keys(session: &Session) -> Result<(), MgmError> {
    let key_handles: Vec<ObjectHandle> = get_filtered_objects(session, ObjectType::WrapKey, false)?;
    println!("Found {} objects", key_handles.len());
    for object in key_handles {
        println!("  {}", session.get_object_info(object.object_id, object.object_type)?);
    }
    Ok(())
}

fn wrap_get_key_properties(session: &Session) -> Result<(), MgmError> {
    println!();
    print_object_properties(session, ObjectType::WrapKey);
    Ok(())
}

fn wrap_delete_key(session: &Session) -> Result<(), MgmError> {
    let keys = get_filtered_objects(session, ObjectType::WrapKey, false)?;
    delete_objects(session, keys)
}

fn get_key_len() -> u32 {
    //let accepted_len = vec![128, 192, 256];
    let mut key_len: u32 = 0;
    while !ACCEPTED_WRAP_KEY_LEN.contains(&key_len) {
        key_len = get_integer_or_default("Enter key length [128, 192, 256] [default 256]: ", 256);
    }
    key_len
}

fn get_key_algo(key_len:u32) -> ObjectAlgorithm {
    match key_len {
        128 => ObjectAlgorithm::Aes128CcmWrap,
        192 => ObjectAlgorithm::Aes192CcmWrap,
        256 => ObjectAlgorithm::Aes256CcmWrap,
        _ => unreachable!()
    }
}

fn get_key_caps(session: &Session, current_authkey:u16) -> Result<(Vec<ObjectCapability>, Vec<ObjectCapability>), MgmError> {
    let capability_options: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities.expect("Cannot read current authentication key's delegated capabilities")
            .into_iter().collect();

    print!("\n  Choose wrap key capabilities:");
    let capabilities: Vec<ObjectCapability> = select_object_capabilities(&capability_options, &capability_options);
    print!("\n  Choose wrap key delegated capabilities:");
    let delegated_capabilities: Vec<ObjectCapability> = select_object_capabilities(&capability_options, &capability_options);
    Ok((capabilities, delegated_capabilities))
}

fn wrap_gen_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    println!();
    let (key_id, label, domains) = get_common_properties();
    let key_algorithm = get_key_algo(get_key_len());
    let (capabilities, delegated_capabilities) = get_key_caps(session, current_authkey)?;

    println!("\n  Generating wrap key with:");
    println!("    Key algorithm: {}", key_algorithm);
    println!("    Label: {}", label);
    println!("    Key ID: {}", key_id);
    print!("    Domains: ");
    domains.iter().for_each(|domain| print!("{}, ", domain));
    println!();
    print!("    Capabilities: ");
    capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!();
    print!("    Delegated capabilities: ");
    delegated_capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!("\n\n");

    if bool::from(get_boolean_answer("Execute? ")) {
        let key = session
            .generate_wrap_key(key_id, &label,  &domains, &capabilities, key_algorithm, &delegated_capabilities)?;
        println!("  Generated wrap key with ID 0x{:04x} on the device", key);
    }
    Ok(())
}

fn wrap_import_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_import_key_subcommand()?;
        match cmd {
            WrapImportKeyCommand::UserGenerated => import_user_generated(session, current_authkey)?,
            WrapImportKeyCommand::DeviceGenerated => import_device_generated(session, current_authkey)?,
            WrapImportKeyCommand::ImportFromShares => import_from_shares(session)?,
            WrapImportKeyCommand::ReturnToMenu => break,
            WrapImportKeyCommand::Exit => std::process::exit(0),
        }
    }
    Ok(())
}

fn get_import_key_subcommand() -> Result<WrapImportKeyCommand, MgmError> {
    let commands: Vec<(String, WrapImportKeyCommand)> = vec![
        ("Import key from user input".to_string(), WrapImportKeyCommand::UserGenerated),
        ("Import key from device generated random number".to_string(), WrapImportKeyCommand::DeviceGenerated),
        ("Import key from shares".to_string(), WrapImportKeyCommand::ImportFromShares),
        ("Return to main menu".to_string(), WrapImportKeyCommand::ReturnToMenu),
        ("Exit".to_string(), WrapImportKeyCommand::Exit),
    ];
    println!();
    Ok(get_menu_option(&commands))
}

fn perform_key_import(
    session: &Session,
    current_authkey:u16,
    key_id: u16,
    label: String,
    domains: Vec<ObjectDomain>,
    key_algo: ObjectAlgorithm,
    wrap_key: Vec<u8>) -> Result<(), MgmError> {

    let (capabilities, delegated_capabilities) = get_key_caps(session, current_authkey)?;

    println!("\n  Import wrap key with:");
    println!("    Key algorithm: {}", key_algo);
    println!("    Label: {}", label);
    println!("    Key ID: {}", key_id);
    print!("    Domains: ");
    domains.iter().for_each(|domain| print!("{}, ", domain));
    println!();
    print!("    Capabilities: ");
    capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!();
    print!("    Delegated capabilities: ");
    delegated_capabilities.iter().for_each(|cap| print!("{:?}, ", cap));
    println!("\n\n");

    if bool::from(get_boolean_answer("Execute? ")) {

        let wrap_id = session
            .import_wrap_key(key_id, &label, &domains, &capabilities, key_algo, &delegated_capabilities, &wrap_key)?;
        println!("  Generated wrap key with ID 0x{:04x} on the device", wrap_id);

        if bool::from(get_boolean_answer("Split wrap key? ")) {
            // Split the wrap key
            let (threshold, shares) = get_threshold_and_shares();
            split_wrapkey(
                wrap_id,
                &domains,
                &capabilities,
                &delegated_capabilities,
                &wrap_key,
                threshold,
                shares,
            );
        }
    }

    Ok(())
}

fn import_user_generated(session:&Session, current_authkey:u16) -> Result<(), MgmError> {
    let (key_id, label, domains) = get_common_properties();
    let key_str = get_string("Enter wrap key in hex: ");
    let wrap_key:Vec<u8> = hex::decode(key_str)?;
    let key_algo = match wrap_key.len() {
        32 => ObjectAlgorithm::Aes256CcmWrap,
        24 => ObjectAlgorithm::Aes192CcmWrap,
        16 => ObjectAlgorithm::Aes128CcmWrap,
        _ => return Err(MgmError::InvalidInput("Wrap key length".parse().unwrap()))
    };

    perform_key_import(session, current_authkey, key_id, label, domains,  key_algo, wrap_key)
}

fn import_device_generated(session:&Session, current_authkey:u16) ->  Result<(), MgmError> {
    println!();
    let (key_id, label, domains) = get_common_properties();
    let key_len = get_key_len();
    let key_algo = get_key_algo(key_len);
    let wrap_key = session.get_random((key_len/8) as usize)?;

    perform_key_import(session, current_authkey, key_id, label, domains,  key_algo, wrap_key)
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let (wrap_id, algo, domains, capabilities, delegated, key) = recover_wrapkey();

    let wrap_id = session
        .import_wrap_key(
            wrap_id,
            "Wrap key",
            &domains,
            &capabilities,
            algo,
            &delegated,
            &key,
        )?;
    println!("Stored wrap key with ID 0x{:04x} on the device\n", wrap_id);

    Ok(())
}

fn backup_device(session: &Session) -> Result<(), MgmError> {
    let wrap_id = get_integer("Enter the wrapping key ID to use for exporting objects:");

    let objects = session.list_objects()?;

    println!("Found {} object(s)", objects.len());

    for object in objects {
        let wrap_result = session.export_wrapped(wrap_id, object.object_type, object.object_id);

        match wrap_result {
            Ok(bytes) => {
                let filename = object_to_file(object.object_id, object.object_type, &bytes)
                    .unwrap_or_else(|err| {
                        println!("Unable to save wrapped object: {}", err);
                        std::process::exit(1);
                    });

                println!(
                    "Successfully exported object {} with ID 0x{:04x} to {}",
                    object.object_type, object.object_id, filename
                );
            }
            Err(err) => println!(
                "Unable to export object {} with ID 0x{:04x} wrapped under key ID 0x{:04x}: {}. Skipping over ...",
                object.object_type, object.object_id, wrap_id, err
            ),
        }
    }
    Ok(())
}

fn object_to_file(id: u16, object_type: ObjectType, data: &[u8]) -> Result<String, String> {
    let path_string = format!("./0x{:04x}-{}.yhw", id, object_type);
    let path = std::path::Path::new(&path_string);

    let mut file = match File::create(path) {
        Err(why) => panic!("couldn't create {}: {}", path.display(), why),
        Ok(file) => file,
    };

    match file.write_all(base64::encode_block(data).as_bytes()) {
        Err(why) => Err(why.to_string()),
        Ok(_) => Ok(path_string.to_owned()),
    }
}

fn restore_device(session: &Session) -> Result<(), MgmError> {
    let wrap_id = get_integer("Enter the wrapping key ID to use for exporting objects:");

    let files: Vec<_> = scan_dir::ScanDir::files()
        .read(".", |iter| {
            iter.filter(|(_, name)| name.ends_with(".yhw"))
                .map(|(entry, _)| entry.path())
                .collect()
        })
        .unwrap();

    for f in files {
        println!("reading {}", &f.display());
        let mut file = File::open(&f).unwrap_or_else(|err| {
            println!("Unable to import read file {}: {}", f.display(), err);
            std::process::exit(1);
        });

        let mut wrap = String::new();
        file.read_to_string(&mut wrap).unwrap_or_else(|err| {
            println!("Unable to read from file {}: {}", f.display(), err);
            std::process::exit(1);
        });

        let data = match base64::decode_block(&wrap) {
            Ok(decoded) => decoded,
            Err(err) => {
                println!(
                    "Unable to decode the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                );
                continue;
            }
        };

        let handle = match session.import_wrapped(wrap_id, &data) {
            Ok(o) => o,
            Err(err) => {
                println!(
                    "Unable to import the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                );
                continue;
            }
        };

        println!(
            "Successfully imported object {}, with ID 0x{:04x}",
            handle.object_type, handle.object_id
        );
    }

    Ok(())
}










fn get_threshold_and_shares() -> (u32, u32) {
    let mut shares;
    let mut threshold;

    loop {
        shares = get_integer("Enter the number of shares:");
        threshold = get_integer("Enter the privacy threshold:");

        if shares == 0 || threshold == 0 {
            println!("The number of shares and the privacy threshold must be greater than zero");
            continue;
        }

        if threshold == 1
            && !Into::<bool>::into(get_boolean_answer(
            "You have chosen a privacy threshold of one.\n\
                 The resulting share(s) will contain the unmodified raw wrap key in plain text.\n\
                 Make sure you understand the implications.\nContinue anyway?",
        ))
        {
            continue;
        }

        if threshold > shares {
            println!("The number of shares must be greater than or equal to the privacy threshold");
            continue;
        }

        break (threshold, shares);
    }
}

fn split_wrapkey(
    wrap_id: u16,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability],
    delegated: &[ObjectCapability],
    key_data: &[u8],
    threshold: u32,
    shares: u32,
) {
    let mut data = Vec::<u8>::new();

    data.push(((wrap_id >> 8) & 0xff) as u8);
    data.push((wrap_id & 0xff) as u8);

    data.append(&mut ObjectDomain::bytes_from_slice(
        domains,
    ));

    data.append(&mut ObjectCapability::bytes_from_slice(
        capabilities,
    ));

    data.append(&mut ObjectCapability::bytes_from_slice(
        delegated,
    ));

    data.extend_from_slice(key_data);

    println!();
    println!("*************************************************************");
    println!("* WARNING! The following shares will NOT be stored anywhere *");
    println!("* Record them and store them safely if you wish to re-use   *");
    println!("* the wrap key for this device in the future                *");
    println!("*************************************************************");

    get_string("Press Enter to start recording key shares");

    let shares = rusty_secrets::generate_shares(threshold as u8, shares as u8, &data)
        .unwrap_or_else(|err| {
            println!("Unable to create shares: {}", err);
            std::process::exit(1);
        });

    for share in shares {
        //loop {
            clear_screen();
            println!("{}", share);
            if Into::<bool>::into(get_boolean_answer("Have you recorded the key share?")) {
                clear_screen();
                get_string("Press any key to display next key share or to return to menu");
            }
        //}
    }

    clear_screen();
}

fn recover_wrapkey() -> (
    u16,
    ObjectAlgorithm,
    Vec<ObjectDomain>,
    Vec<ObjectCapability>,
    Vec<ObjectCapability>,
    Vec<u8>,
) {
    let shares = get_integer::<u16>("Enter the number of shares:");

    let mut shares_vec = Vec::new();

    let mut key_len = 0;
    let mut key_algorithm:ObjectAlgorithm = ObjectAlgorithm::Aes256CcmWrap;
    while shares_vec.len() != shares as usize {
        let share = get_string(&format!("Enter share number {}:", shares_vec.len() + 1));
        println!("Received share {} with length {}", share, share.len());

        match share.len() {
            74 => {
                if !SHARE_RE_256.is_match(&share) || (key_len != 0 && key_len != 256) {
                    println!("Malformed share");
                    continue;
                }
                key_len = 256;
                key_algorithm = ObjectAlgorithm::Aes256CcmWrap;
            }
            63 => {
                if !SHARE_RE_192.is_match(&share) || (key_len != 0 && key_len != 192) {
                    println!("Malformed share");
                    continue;
                }
                key_len = 192;
                key_algorithm = ObjectAlgorithm::Aes192CcmWrap;
            }

            52 => {
                if !SHARE_RE_128.is_match(&share) || (key_len != 0 && key_len != 128) {
                    println!("Malformed share");
                    continue;
                }
                key_len = 128;
                key_algorithm = ObjectAlgorithm::Aes128CcmWrap;

            }
            _ => {
                println!("Malformed share");
                continue;
            }
        }

        shares_vec.push(share);
        clear_screen();
    }

    let secret = rusty_secrets::recover_secret(shares_vec).unwrap_or_else(|err| {
        println!("Unable to recover key: {}", err);
        std::process::exit(1);
    });

    // TODO(adma): magic numbers ...

    if secret.len() != 2 + 2 + 8 + 8 + (key_len/8) {
        println!(
            "Wrong length for recovered secret: expected {}, found {}",
            2 + 2 + 8 + 8 + (key_len/8),
            secret.len()
        )
    }

    let wrap_id = ((u16::from(secret[0])) << 8) | u16::from(secret[1]);

    let domains = ObjectDomain::from_bytes(&secret[2..4]).unwrap_or_else(|err| {
        println!("Unable to parse domains: {}", err);
        std::process::exit(1);
    });

    let capabilities = ObjectCapability::from_bytes(&secret[4..12]).unwrap_or_else(|err| {
        println!("Unable to parse capabilities: {}", err);
        std::process::exit(1);
    });

    let delegated = ObjectCapability::from_bytes(&secret[12..20]).unwrap_or_else(|err| {
        println!("Unable to parse delegated capabilities: {}", err);
        std::process::exit(1);
    });

    let key = &secret[20..];

    (wrap_id, key_algorithm, domains, capabilities, delegated, key.to_vec())
}

fn clear_screen() {
    std::process::Command::new("clear")
        .status()
        .unwrap_or_else(|err| {
            println!("Unable to clear terminal screen: {}", err);
            std::process::exit(1);
        });
}
