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

use std::fmt;
use std::fmt::Display;

use std::fs::File;
use std::io::{Read};
use std::sync::LazyLock;
use ::base64::Engine;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::error::MgmError;
use crate::util::{convert_handlers, delete_objects, get_delegated_capabilities, get_directory, get_label, get_new_object_basics, list_objects, print_object_properties, select_capabilities, select_multiple_objects, select_one_object, write_bytes_to_file};
use regex::Regex;
use rusty_secrets::recover_secret;
use crate::MAIN_STRING;

static WRAP_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Wrap keys", MAIN_STRING));

const WRAP_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::ExportWrapped,
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportableUnderWrap];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapCommand {
    #[default]
    List,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    Backup,
    Restore,
    ReturnToMainMenu,
    Exit,
}

impl Display for WrapCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WrapCommand::List => write!(f, "List"),
            WrapCommand::GetKeyProperties => write!(f, "Print object properties"),
            WrapCommand::Generate => write!(f, "Generate"),
            WrapCommand::Import => write!(f, "Import"),
            WrapCommand::Delete => write!(f, "Delete"),
            WrapCommand::Backup => write!(f, "Backup YubiHSM objects"),
            WrapCommand::Restore => write!(f, "Restore YubiHSM objects"),
            WrapCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            WrapCommand::Exit => write!(f, "Exit"),
        }
    }
}

// const ACCEPTED_WRAP_KEY_LEN: [u32;3] = [128, 192, 256];
const WRAP_SPLIT_PREFIX_LEN: usize = 20; // 2 object ID bytes + 2 domains bytes +
                                         // 8 capabilities bytes +
                                         // 8 delegated capabilities bytes

static SHARE_RE_256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap());
static SHARE_RE_192: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap());
static SHARE_RE_128: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap());

pub fn exec_wrap_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        println!("\n{}", *WRAP_STRING);

        let cmd = get_wrap_command(authkey)?;
        let result = match cmd {
            WrapCommand::List => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::List);
                list(session)
            },
            WrapCommand::GetKeyProperties => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::GetKeyProperties);
                print_key_properties(session)
            },
            WrapCommand::Generate => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Generate);
                generate(session, authkey)
            },
            WrapCommand::Import => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Import);
                import(session, authkey)
            },
            WrapCommand::Delete => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Delete);
                delete(session)
            },
            WrapCommand::Backup => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Backup);
                backup_device(session)
            },
            WrapCommand::Restore => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Restore);
                restore_device(session)
            },
            WrapCommand::ReturnToMainMenu => return Ok(()),
            WrapCommand::Exit => std::process::exit(0),
        };

        if let Err(err) = result {
            cliclack::log::error(err)?;
        }
    }
}

fn get_wrap_command(authkey: &ObjectDescriptor) -> Result<WrapCommand, MgmError> {
    let capabilities = &authkey.capabilities;

    let mut commands = cliclack::select("");
    commands = commands.item(WrapCommand::List, WrapCommand::List, "");
    commands = commands.item(WrapCommand::GetKeyProperties, WrapCommand::GetKeyProperties, "");
    if capabilities.contains(&ObjectCapability::GenerateWrapKey) {
        commands = commands.item(WrapCommand::Generate, WrapCommand::Generate, "");
    }
    if capabilities.contains(&ObjectCapability::PutWrapKey) {
        commands = commands.item(WrapCommand::Import, WrapCommand::Import, "");
    }
    if capabilities.contains(&ObjectCapability::DeleteWrapKey) {
        commands = commands.item(WrapCommand::Delete, WrapCommand::Delete, "");
    }
    if capabilities.contains(&ObjectCapability::ExportWrapped) {
        commands = commands.item(WrapCommand::Backup, WrapCommand::Backup,
                                 "Writes files ending with .yhw to backup directory");
    }
    if capabilities.contains(&ObjectCapability::ImportWrapped) {
        commands = commands.item(WrapCommand::Restore, WrapCommand::Restore,
                                 "Reads files ending with .yhw from backup directory");
    }
    commands = commands.item(WrapCommand::ReturnToMainMenu, WrapCommand::ReturnToMainMenu, "");
    commands = commands.item(WrapCommand::Exit, WrapCommand::Exit, "");
    Ok(commands.interact()?)
}

fn get_all_wrap_key(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    Ok(session.list_objects_with_filter(
        0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?)
}

fn list(session: &Session) -> Result<(), MgmError> {
    list_objects(session, &get_all_wrap_key(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_all_wrap_key(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_wrap_key(session)?)
}

// fn get_key_len() -> Result<u32, MgmError> {
//     let mut key_len = cliclack::select("Select key length");
//     for l in ACCEPTED_WRAP_KEY_LEN {
//         key_len = key_len.item(l, l, "");
//     }
//     Ok(key_len.interact()?)
// }
//
// fn get_key_algo(key_len:u32) -> ObjectAlgorithm {
//     match key_len {
//         128 => ObjectAlgorithm::Aes128CcmWrap,
//         192 => ObjectAlgorithm::Aes192CcmWrap,
//         256 => ObjectAlgorithm::Aes256CcmWrap,
//         _ => unreachable!()
//     }
// }

fn get_new_key_note(key_desc: &ObjectDescriptor) -> String {
    key_desc.to_string()
            .replace("Sequence:  0\t", "")
            .replace("Origin: Generated\t", "")
            .replace("\t", "\n")
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let algorithm = cliclack::select("Choose key algorithm:")
        .item(ObjectAlgorithm::Aes128CcmWrap, "AES128", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes128CcmWrap))
        .item(ObjectAlgorithm::Aes192CcmWrap, "AES192", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes192CcmWrap))
        .item(ObjectAlgorithm::Aes256CcmWrap, "AES256", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes256CcmWrap))
        .interact()?;

    let mut new_key = get_new_object_basics(authkey, ObjectType::WrapKey, &WRAP_KEY_CAPABILITIES, &[])?;
    let delegated = select_capabilities(
        "Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;
    new_key.delegated_capabilities = if delegated.is_empty() {None} else {Some(delegated)};
    new_key.algorithm = algorithm;

    cliclack::note("Generating wrap key with:",get_new_key_note(&new_key))?;

    if cliclack::confirm("Generate wrap key?").interact()? {
        new_key.id = session
            .generate_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice())?;

        cliclack::log::success(
            format!("Generated wrap key with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    if cliclack::confirm("Re-create from shares?").interact()? {
        import_from_shares(session)
    } else {
        import_full_key(session, authkey)
    }
}

fn import_full_key(session:&Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key:String = cliclack::input("Enter wrap key in HEX format:")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else if input.len() != 32 && input.len() != 48 && input.len() != 64 {
                Err("Input must be 16, 24 or 32 bytes long")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let key:Vec<u8> = hex::decode(key)?;
    let algorithm = match key.len() {
        32 => ObjectAlgorithm::Aes256CcmWrap,
        24 => ObjectAlgorithm::Aes192CcmWrap,
        16 => ObjectAlgorithm::Aes128CcmWrap,
        _ => unreachable!()
    };

    let mut new_key = get_new_object_basics(authkey, ObjectType::WrapKey, &WRAP_KEY_CAPABILITIES, &[])?;
    let delegated = select_capabilities("Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;
    new_key.delegated_capabilities = if delegated.is_empty() {None} else {Some(delegated)};
    new_key.algorithm = algorithm;

    cliclack::note("Import wrap key with:", get_new_key_note(&new_key))?;

    if cliclack::confirm("Import wrap key?").interact()? {
        let key_id = session
            .import_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice(),
                &key)?;

        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", key_id))?;
    }

    if cliclack::confirm("Split wrap key? ").interact()? {
        // Split the wrap key
        let shares = get_shares()?;
        let threshold = get_threshold(shares)?;

        split_wrapkey(
            new_key.id,
            &new_key.domains,
            &new_key.capabilities,
            get_delegated_capabilities(&new_key).as_slice(),
            &key,
            threshold,
            shares,
        )?;
    }

    Ok(())
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let (mut new_key, key) = recover_wrapkey()?;

    new_key.label = get_label()?;

    cliclack::note("Import wrap key with:", get_new_key_note(&new_key))?;

    if cliclack::confirm("Import wrap key?").interact()? {
        let key_id = session
            .import_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice(),
                &key,
            )?;
        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", key_id))?;
    }
    Ok(())
}

fn backup_device(session: &Session) -> Result<(), MgmError> {
    let wrap_keys = session.list_objects_with_filter(
        0,
        ObjectType::WrapKey,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportWrapped])?;
    let wrapping_key = select_one_object(
        "Select the wrapping key to use for exporting objects:",
        convert_handlers(session, &wrap_keys)?)?;

    let exportable_objects = session.list_objects_with_filter(
        0,
        ObjectType::Any,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportableUnderWrap])?;
    cliclack::log::info(format!("Found {} objects marked as exportable-under-wrap", exportable_objects.len()))?;
    let export_objects = select_multiple_objects(
        "Select objects to export",
        convert_handlers(session, &exportable_objects)?, true)?;

    let dir: String = get_directory("Enter path to backup directory:")?;

    for object in export_objects {
        match session.export_wrapped(wrapping_key.id, object.object_type, object.id) {
            Ok(bytes) => {
                object_to_file(dir.clone(), object.id, object.object_type, &bytes)?;
            }
            Err(err) => cliclack::log::warning(format!(
                "Unable to export {} object with ID 0x{:04x} wrapped under key ID 0x{:04x}: {}. Skipping over ...",
                object.object_type, object.id, wrapping_key.id, err))?
        }
    }
    Ok(())
}

pub fn object_to_file(dir: String, id: u16, object_type: ObjectType, data: &[u8]) -> Result<String, MgmError> {
    let filename = format!("0x{:04x}-{}.yhw", id, object_type);
    let base64 = ::base64::engine::general_purpose::STANDARD.encode(data);
    write_bytes_to_file(base64.as_bytes().to_vec(), &dir, filename.as_str())?;
    Ok(filename)
}

fn restore_device(session: &Session) -> Result<(), MgmError> {
    let wrap_keys = session.list_objects_with_filter(
        0,
        ObjectType::WrapKey,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ImportWrapped])?;
    let wrapping_key = select_one_object(
        "Select the wrapping key to use for importing objects:",
        convert_handlers(session, &wrap_keys)?)?;

    let dir = get_directory("Enter backup directory:")?;

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

        let data = match ::base64::engine::general_purpose::STANDARD.decode(wrap) {
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
    let t: String = cliclack::input("Enter the number of shared necessary to re-create:")
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
        * Save them and store them safely if you wish to re-use   *\n\
        * the wrap key for this device in the future                *\n\
        *************************************************************")?;

    let _str: String = cliclack::input("Press Enter to start saving key shares").required(false).interact()?;

    let shares = rusty_secrets::generate_shares(threshold as u8, shares as u8, &data)?;

    for share in shares {
        cliclack::clear_screen()?;
        cliclack::note("", share)?;
        if cliclack::confirm("Have you saved the key share?").interact()? {
            cliclack::clear_screen()?;
            let _str: String = cliclack::input(
                "Press any key to display next key share or to return to menu").required(false).interact()?;
        }
    }

    cliclack::clear_screen()?;
    Ok(())
}

fn recover_wrapkey() -> Result<(ObjectDescriptor, Vec<u8>), MgmError> {

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
        Err(err) => return Err(MgmError::Error(format!("Unable to recover wrap key: {}", err))),
    };

    if secret.len() != WRAP_SPLIT_PREFIX_LEN + (key_len/8) {
        return Err(MgmError::Error(format!(
            "Wrong length for recovered secret: expected {}, found {}",
            WRAP_SPLIT_PREFIX_LEN + (key_len/8),
            secret.len()
        )));
    }

    let mut new_key = ObjectDescriptor::new();
    new_key.object_type = ObjectType::WrapKey;
    new_key.algorithm = key_algorithm;
    new_key.id = ((u16::from(secret[0])) << 8) | u16::from(secret[1]);
    new_key.domains = ObjectDomain::from_bytes(&secret[2..4])?;
    new_key.capabilities = ObjectCapability::from_bytes(&secret[4..12])?;
    let delegated = ObjectCapability::from_bytes(&secret[12..20])?;
    new_key.delegated_capabilities = if delegated.is_empty() {None} else {Some(delegated)};

    let key = &secret[20..];

    Ok((new_key, key.to_vec()))
}
