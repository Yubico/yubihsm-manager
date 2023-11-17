use std::collections::HashSet;

use std::fs::File;
use std::io::{Read};
use std::path::Path;
use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use error::MgmError;
use util::{delete_objects, get_domains, get_id, get_label, get_object_properties_str_with_delegated, list_objects, print_object_properties, select_multiple_objects, select_object_capabilities, select_one_object, write_file};
use regex::Regex;
use rusty_secrets::recover_secret;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapCommand {
    #[default]
    ListKeys,
    GetKeyProperties,
    GenerateKey,
    ImportKey,
    DeleteKey,
    PerformBackup,
    PerformRestore,
    ReturnToMainMenu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapImportKeyCommand {
    #[default]
    UserGenerated,
    DeviceGenerated,
    ImportFromShares,
    ReturnToMenu,
}

const ACCEPTED_WRAP_KEY_LEN: [u32;3] = [128, 192, 256];
const WRAP_SPLIT_PREFIX_LEN: usize = 20; // 2 object ID bytes + 2 domains bytes +
                                         // 8 capabilities bytes +
                                         // 8 delegated capabilities bytes

lazy_static! {
    static ref SHARE_RE_256: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap();
    static ref SHARE_RE_192: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap();
    static ref SHARE_RE_128: Regex = Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap();
}

pub fn exec_wrap_command(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_wrap_command(session, current_authkey)?;
        let result = match cmd {
            WrapCommand::ListKeys => wrap_list_keys(session),
            WrapCommand::GetKeyProperties => wrap_get_key_properties(session),
            WrapCommand::GenerateKey => wrap_gen_key(session, current_authkey),
            WrapCommand::ImportKey => wrap_import_key(session, current_authkey),
            WrapCommand::DeleteKey => wrap_delete_key(session),
            WrapCommand::PerformBackup => backup_device(session),
            WrapCommand::PerformRestore => restore_device(session),
            WrapCommand::ReturnToMainMenu => return Ok(()),
        };

        if let Err(err) = result {
            cliclack::log::error(err)?;
        }
    }
}

fn get_wrap_command(session: &Session, current_authkey: u16) -> Result<WrapCommand, MgmError> {
    let capabilities: HashSet<ObjectCapability> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?.capabilities.into_iter().collect();

    let mut commands = cliclack::select("");
    commands = commands.item(WrapCommand::ListKeys, "List keys", "");
    commands = commands.item(WrapCommand::GetKeyProperties, "Get key properties", "");
    if capabilities.contains(&ObjectCapability::GenerateWrapKey) {
        commands = commands.item(WrapCommand::GenerateKey, "Generate key", "");
    }
    if capabilities.contains(&ObjectCapability::PutWrapKey) {
        commands = commands.item(WrapCommand::ImportKey, "Import key", "");
    }
    if capabilities.contains(&ObjectCapability::DeleteWrapKey) {
        commands = commands.item(WrapCommand::DeleteKey, "Delete key", "");
    }
    if capabilities.contains(&ObjectCapability::ExportWrapped) {
        commands = commands.item(WrapCommand::PerformBackup, "Backup YubiHSM content",
                                 "Writes files ending with .yhw to current directory");
    }
    if capabilities.contains(&ObjectCapability::ImportWrapped) {
        commands = commands.item(WrapCommand::PerformRestore, "Restore YubiHSM content",
                                 "Reads files ending with .yhw from currant directory");
    }
    commands = commands.item(WrapCommand::ReturnToMainMenu, "Return to main menu", "");
    Ok(commands.interact()?)
}

fn get_all_wrap_key(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    Ok(session.list_objects_with_filter(
        0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?)
}

fn wrap_list_keys(session: &Session) -> Result<(), MgmError> {
    list_objects(session, &get_all_wrap_key(session)?)
}

fn wrap_get_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_wrap_key(session)?)
}

fn wrap_delete_key(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_wrap_key(session)?)
}

fn get_key_len() -> Result<u32, MgmError> {
    let mut key_len = cliclack::select("Select key length");
    for l in ACCEPTED_WRAP_KEY_LEN {
        key_len = key_len.item(l, l, "");
    }
    Ok(key_len.interact()?)
}

fn get_key_algo(key_len:u32) -> ObjectAlgorithm {
    match key_len {
        128 => ObjectAlgorithm::Aes128CcmWrap,
        192 => ObjectAlgorithm::Aes192CcmWrap,
        256 => ObjectAlgorithm::Aes256CcmWrap,
        _ => unreachable!()
    }
}

fn get_key_capabilities(session: &Session, current_authkey:u16)
    -> Result<(Vec<ObjectCapability>, Vec<ObjectCapability>), MgmError> {
    let Some(capability_options) = session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
        .delegated_capabilities else {
        return Err(MgmError::Error("Cannot read current authentication key's delegated capabilities".to_string()))
    };
    let capabilities = select_object_capabilities(
        "Select wrap key capabilities",
        true,
        false,
        &capability_options,
        &capability_options
    )?;

    let delegated_capabilities = select_object_capabilities(
        "Select wrap key delegated capabilities:",
        true,
        false,
        &capability_options,
        &capability_options
    )?;
    Ok((capabilities, delegated_capabilities))
}


fn wrap_gen_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;
    let key_algorithm = get_key_algo(get_key_len()?);
    let (capabilities, delegated_capabilities) = get_key_capabilities(session, current_authkey)?;

    cliclack::note("Generating wrap key with:",
                   get_object_properties_str_with_delegated(
                       &key_algorithm,
                       &label,
                       key_id,
                       &domains,
                       &capabilities,
                       &delegated_capabilities))?;

    if cliclack::confirm("Generate wrap key?").interact()? {
        let key_id = session
            .generate_wrap_key(key_id, &label,  &domains, &capabilities, key_algorithm, &delegated_capabilities)?;

        cliclack::log::success(
            format!("Generated wrap key with ID 0x{:04x} on the device", key_id))?;
    }
    Ok(())
}

fn wrap_import_key(session: &Session, current_authkey: u16) -> Result<(), MgmError> {
    loop {
        let cmd = get_import_key_subcommand()?;
        if let Err(err) = match cmd {
            WrapImportKeyCommand::UserGenerated => import_user_generated(session, current_authkey),
            WrapImportKeyCommand::DeviceGenerated => import_device_generated(session, current_authkey),
            WrapImportKeyCommand::ImportFromShares => import_from_shares(session),
            WrapImportKeyCommand::ReturnToMenu => break,
        } {
            cliclack::log::error(err)?;
        }
    }
    Ok(())
}

fn get_import_key_subcommand() -> Result<WrapImportKeyCommand, MgmError> {
    Ok(cliclack::select("")
        .item(WrapImportKeyCommand::UserGenerated, "Import key from user input", "")
        .item(WrapImportKeyCommand::DeviceGenerated, "Import key from device generated random number",
              "get-pseudo-random function will be called to generated a random number that will be used as \
              the wrap key to import")
        .item(WrapImportKeyCommand::ImportFromShares, "Import key from shares", "")
        .item(WrapImportKeyCommand::ReturnToMenu, "Return to main menu", "")
        .interact()?)
}

fn perform_key_import(
    session: &Session,
    current_authkey:u16,
    key_id: u16,
    label: String,
    domains: Vec<ObjectDomain>,
    key_algorithm: ObjectAlgorithm,
    wrap_key: Vec<u8>) -> Result<(), MgmError> {

    let (capabilities, delegated_capabilities) = get_key_capabilities(session, current_authkey)?;

    cliclack::note("Import wrap key with:",
                   get_object_properties_str_with_delegated(
                       &key_algorithm,
                       &label,
                       key_id,
                       &domains,
                       &capabilities,
                       &delegated_capabilities))?;

    if cliclack::confirm("Import wrap key?").interact()? {
        let key_id = session
            .import_wrap_key(key_id, &label, &domains, &capabilities, key_algorithm, &delegated_capabilities, &wrap_key)?;

        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", key_id))?;
    }

    if cliclack::confirm("Split wrap key? ").interact()? {
        // Split the wrap key
        let shares = get_shares()?;
        let threshold = get_threshold(shares)?;

        split_wrapkey(
            key_id,
            &domains,
            &capabilities,
            &delegated_capabilities,
            &wrap_key,
            threshold,
            shares,
        )?;
    }

    Ok(())
}

fn import_user_generated(session:&Session, current_authkey:u16) -> Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;
    let key_str:String = cliclack::input("Enter wrap key in hex:")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let wrap_key:Vec<u8> = hex::decode(key_str)?;
    let key_algo = match wrap_key.len() {
        32 => ObjectAlgorithm::Aes256CcmWrap,
        24 => ObjectAlgorithm::Aes192CcmWrap,
        16 => ObjectAlgorithm::Aes128CcmWrap,
        _ => return Err(MgmError::InvalidInput("Wrap key length".to_string()))
    };

    perform_key_import(session, current_authkey, key_id, label, domains,  key_algo, wrap_key)
}

fn import_device_generated(session:&Session, current_authkey:u16) ->  Result<(), MgmError> {
    let key_id = get_id()?;
    let label = get_label()?;
    let domains = get_domains()?;
    let key_len = get_key_len()?;
    let key_algo = get_key_algo(key_len);
    let wrap_key = session.get_random((key_len/8) as usize)?;

    perform_key_import(session, current_authkey, key_id, label, domains,  key_algo, wrap_key)
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let label = get_label()?;

    let (key_id,
        key_algorithm,
        domains,
        capabilities,
        delegated_capabilities,
        key) = recover_wrapkey()?;

    cliclack::note("Import wrap key with:",
                   get_object_properties_str_with_delegated(
                       &key_algorithm,
                       &label,
                       key_id,
                       &domains,
                       &capabilities,
                       &delegated_capabilities))?;

    if cliclack::confirm("Import wrap key?").interact()? {
        let key_id = session
            .import_wrap_key(
                key_id,
                &label,
                &domains,
                &capabilities,
                key_algorithm,
                &delegated_capabilities,
                &key,
            )?;
        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", key_id))?;
    }
    Ok(())
}

fn backup_device(session: &Session) -> Result<(), MgmError> {
    let available_wrap_keys = session.list_objects_with_filter(
        0,
        ObjectType::WrapKey,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportWrapped])?;
    let wrapping_key = select_one_object(
        session,
        available_wrap_keys,
        "Select the wrapping key to use for exporting objects:")?;

    let exportable_objects = session.list_objects_with_filter(
        0,
        ObjectType::Any,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportableUnderWrap])?;
    cliclack::log::info(format!("Found {} objects marked as exportable-under-wrap", exportable_objects.len()))?;
    let export_objects = select_multiple_objects(
        session, exportable_objects,
        "Select objects to export (Only objects with the capability exportable-under-wrap are listed)", true)?;

    for object in export_objects {
        match session.export_wrapped(wrapping_key.id, object.object_type, object.id) {
            Ok(bytes) => {
                let filename = object_to_file(object.id, object.object_type, &bytes)?;
                cliclack::log::success(format!(
                    "Successfully exported object {} with ID 0x{:04x} to {}",
                    object.object_type, object.id, filename))?;
            }
            Err(err) => cliclack::log::warning(format!(
                "Unable to export {} object with ID 0x{:04x} wrapped under key ID 0x{:04x}: {}. Skipping over ...",
                object.object_type, object.id, wrapping_key.id, err))?
        }
    }
    Ok(())
}

pub fn object_to_file(id: u16, object_type: ObjectType, data: &[u8]) -> Result<String, MgmError> {
    let dir: String = get_backup_directory()?;
    let filename = format!("{}/0x{:04x}-{}.yhw", dir, id, object_type);
    write_file(base64::encode_block(data).as_bytes().to_vec(), &filename)?;
    Ok(filename)
}

fn restore_device(session: &Session) -> Result<(), MgmError> {
    let available_wrap_keys = session.list_objects_with_filter(
        0,
        ObjectType::WrapKey,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ImportWrapped])?;
    let wrapping_key = select_one_object(
        session,
        available_wrap_keys,
        "Select the wrapping key to use for importing objects:")?;

    let dir = get_backup_directory()?;
    let files: Vec<_> = match scan_dir::ScanDir::files()
        .read(dir.clone(), |iter| {
            iter.filter(|(_, name)| name.ends_with(".yhw"))
                .map(|(entry, _)| entry.path())
                .collect()
        }) {
        Ok(f) => f,
        Err(err) => {
            cliclack::log::error(err)?;
            return Err(MgmError::Error("Failed to read files".to_string()))
        }
    };

    if files.is_empty() {
        cliclack::log::info(format!("No backup files were found in {}", dir))?;
        return Ok(())
    }

    for f in files {
        cliclack::log::info(format!("reading {}", &f.display()))?;
        let mut file = File::open(&f)?;

        let mut wrap = String::new();
        file.read_to_string(&mut wrap)?;

        let data = match base64::decode_block(&wrap) {
            Ok(decoded) => decoded,
            Err(err) => {
                cliclack::log::warning(format!(
                    "Unable to decode the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                ))?;
                continue;
            }
        };

        let handle = match session.import_wrapped(wrapping_key.id, &data) {
            Ok(o) => o,
            Err(err) => {
                cliclack::log::warning(format!(
                    "Unable to import the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                ))?;
                continue;
            }
        };

        cliclack::log::success(format!(
            "Successfully imported object {}, with ID 0x{:04x}",
            handle.object_type, handle.object_id
        ))?;
    }

    Ok(())
}

fn get_backup_directory() -> Result<String, MgmError> {
    let dir: String = cliclack::input("Enter backup directory?")
        .placeholder("Default is current directory")
        .default_input(".")
        .validate(|input: &String| {
            if !Path::new(input).exists() {
                Err("No such directory. Please enter an existing path.")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(dir)
}










pub fn get_shares() -> Result<u16, MgmError> {
    let n: String = cliclack::input("Enter the number of shares:")
        .placeholder("Must be greater than 0")
        .validate(|input: &String| {
            if input.parse::<u16>().is_err() {
                Err("Must be a number")
            } else if input.parse::<u16>().unwrap() == 0 {
                Err("Must be greater than zero")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let n = match n.parse::<u16>() {
        Ok(s) => s,
        Err(err) => {
            cliclack::log::error(err)?;
            return Err(MgmError::Error("Failed to parse number of shares".to_string()))
        }
    };
    Ok(n)
}

pub fn get_threshold(shares:u16) -> Result<u16, MgmError> {
    //let shares_clone = shares;
    let t: String = cliclack::input("Enter the privacy threshold:")
        .placeholder("Must be greater than 0 and less than the number of shares")
        .validate(move |input: &String| {
            if input.parse::<u16>().is_err() {
                Err("Must be a number")
            } else if input.parse::<u16>().unwrap() == 0 || input.parse::<u16>().unwrap() > shares {
                Err("Must be greater than zero and less than the number of shares")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let t = match t.parse::<u16>() {
        Ok(t) => t,
        Err(err) => {
            cliclack::log::error(err)?;
            return Err(MgmError::Error("Failed to parse threshold number".to_string()))
        }
    };

    if t == 1 {
        cliclack::log::warning("You have chosen a privacy threshold of one.\n\
                 The resulting share(s) will contain the unmodified raw wrap key in plain text.\n\
                 Make sure you understand the implications.")?;
        if !cliclack::confirm("Continue anyway?").interact()? {
            return  get_threshold(shares);
        }
    }

    Ok(t)
}

pub fn split_wrapkey(
    wrap_id: u16,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability],
    delegated: &[ObjectCapability],
    key_data: &[u8],
    threshold: u16,
    shares: u16,
) -> Result<(), MgmError> {
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

    cliclack::log::warning(
        "*************************************************************\n\
        * WARNING! The following shares will NOT be stored anywhere *\n\
        * Record them and store them safely if you wish to re-use   *\n\
        * the wrap key for this device in the future                *\n\
        *************************************************************")?;

    let _str: String = cliclack::input("Press Enter to start recording key shares").required(false).interact()?;

    let shares = rusty_secrets::generate_shares(threshold as u8, shares as u8, &data)?;

    for share in shares {
        cliclack::clear_screen()?;
        cliclack::note("", share)?;
        if cliclack::confirm("Have you recorded the key share?").interact()? {
            cliclack::clear_screen()?;
            let _str: String = cliclack::input(
                "Press any key to display next key share or to return to menu").required(false).interact()?;
        }
    }

    cliclack::clear_screen()?;
    Ok(())
}

fn recover_wrapkey() -> Result<(
    u16,
    ObjectAlgorithm,
    Vec<ObjectDomain>,
    Vec<ObjectCapability>,
    Vec<ObjectCapability>,
    Vec<u8>,
), MgmError> {

    let shares = get_shares()?;

    let mut shares_vec = Vec::new();

    let mut key_len = 0;
    let mut key_algorithm:ObjectAlgorithm = ObjectAlgorithm::Aes256CcmWrap;
    while shares_vec.len() != shares as usize {
        let share: String = cliclack::input(format!("Enter share number {}:", shares_vec.len() + 1)).interact()?;
        cliclack::log::info(format!("Received share {} with length {}", share, share.len()))?;

        match share.len() {
            74 => {
                if !SHARE_RE_256.is_match(&share) || (key_len != 0 && key_len != 256) {
                    cliclack::log::warning("Malformed share. Continuing...")?;
                    continue;
                }
                key_len = 256;
                key_algorithm = ObjectAlgorithm::Aes256CcmWrap;
            }
            63 => {
                if !SHARE_RE_192.is_match(&share) || (key_len != 0 && key_len != 192) {
                    cliclack::log::warning("Malformed share. Continuing...")?;
                    continue;
                }
                key_len = 192;
                key_algorithm = ObjectAlgorithm::Aes192CcmWrap;
            }

            52 => {
                if !SHARE_RE_128.is_match(&share) || (key_len != 0 && key_len != 128) {
                    cliclack::log::warning("Malformed share. Continuing...")?;
                    continue;
                }
                key_len = 128;
                key_algorithm = ObjectAlgorithm::Aes128CcmWrap;

            }
            _ => {
                cliclack::log::warning("Malformed share. Continuing...")?;
                continue;
            }
        }

        shares_vec.push(share);
        cliclack::clear_screen()?;
    }

    let secret = match recover_secret(shares_vec) {
        Ok(sec) => sec,
        Err(err) => return Err(MgmError::Error(format!("Unable to recover wrap key: {}", err.to_string()))),
    };

    if secret.len() != WRAP_SPLIT_PREFIX_LEN + (key_len/8) {
        return Err(MgmError::Error(format!(
            "Wrong length for recovered secret: expected {}, found {}",
            WRAP_SPLIT_PREFIX_LEN + (key_len/8),
            secret.len()
        )));
    }

    let wrap_id = ((u16::from(secret[0])) << 8) | u16::from(secret[1]);

    let domains = ObjectDomain::from_bytes(&secret[2..4])?;

    let capabilities = ObjectCapability::from_bytes(&secret[4..12])?;

    let delegated = ObjectCapability::from_bytes(&secret[12..20])?;

    let key = &secret[20..];

    Ok((wrap_id, key_algorithm, domains, capabilities, delegated, key.to_vec()))
}
