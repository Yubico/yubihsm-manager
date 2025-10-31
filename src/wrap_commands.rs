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

use std::sync::LazyLock;
use regex::Regex;
use openssl::base64;
use openssl::bn::BigNum;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::error::MgmError;
use crate::util::{convert_handlers, delete_objects, get_delegated_capabilities, get_directory, get_label, get_new_object_basics, list_objects, print_object_properties, select_capabilities, select_multiple_objects, select_one_object, write_bytes_to_file, read_pem_file, contains_all};
use regex::Regex;
use rusty_secrets::recover_secret;
use crate::sym_commands::{AES_KEY_CAPABILITIES};
use crate::asym_commands::{get_hashed_bytes, RSA_KEY_CAPABILITIES, EC_KEY_CAPABILITIES, ED_KEY_CAPABILITIES, RSA_KEY_ALGORITHM, EC_KEY_ALGORITHM};
use crate::MAIN_STRING;

static WRAP_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Wrap keys", MAIN_STRING));
static SHARE_RE_256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap());
static SHARE_RE_192: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap());
static SHARE_RE_128: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap());


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapKeyType {
    #[default]
    Aes,
    Rsa,
    RsaPublic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapType {
    #[default]
    Object,
    Key,
}

impl Display for WrapType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WrapType::Object => write!(f, "YubiHSM2 Object"),
            WrapType::Key => write!(f, "Key data only"),
        }
    }
}


const AES_WRAP_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::ExportWrapped,
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportableUnderWrap];

const RSA_WRAP_KEY_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportableUnderWrap];

const PUBLIC_WRAP_KEY_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::ExportWrapped,
    ObjectCapability::ExportableUnderWrap];



#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WrapCommand {
    #[default]
    List,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    GetPublicKey,
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
            WrapCommand::GetPublicKey => write!(f, "Get public RSA wrap key"),
            WrapCommand::Backup => write!(f, "Backup YubiHSM objects"),
            WrapCommand::Restore => write!(f, "Restore YubiHSM objects"),
            WrapCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            WrapCommand::Exit => write!(f, "Exit"),
        }
    }
}

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
            WrapCommand::GetPublicKey => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::GetPublicKey);
                get_public_key(session)
            },
            WrapCommand::Backup => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Backup);
                backup_device(session, authkey)
            },
            WrapCommand::Restore => {
                println!("\n{} > {}\n", *WRAP_STRING, WrapCommand::Restore);
                restore_device(session, authkey)
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
    commands = commands.item(WrapCommand::GetPublicKey, WrapCommand::GetPublicKey, "");
    if capabilities.contains(&ObjectCapability::ExportWrapped) {
        commands = commands.item(WrapCommand::ExportWrapped, WrapCommand::ExportWrapped,
                                 "Writes files ending with .yhw to specified directory");
    }
    if capabilities.contains(&ObjectCapability::ImportWrapped) {
        commands = commands.item(WrapCommand::ImportWrapped, WrapCommand::ImportWrapped,
                                 "Reads one file ending with .yhw");
    }
    if capabilities.contains(&ObjectCapability::ExportWrapped) {
        commands = commands.item(WrapCommand::BackupDevice, WrapCommand::BackupDevice,
                                 "Export all exportable objects to a backup directory");
    }
    if capabilities.contains(&ObjectCapability::ImportWrapped) {
        commands = commands.item(WrapCommand::RestoreDevice, WrapCommand::RestoreDevice,
                                 "Import objects from all files ending with .yhw from backup directory");
    }
    commands = commands.item(WrapCommand::ReturnToMainMenu, WrapCommand::ReturnToMainMenu, "");
    commands = commands.item(WrapCommand::Exit, WrapCommand::Exit, "");
    Ok(commands.interact()?)
}

fn get_all_wrap_key(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.list_objects_with_filter(
        0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    keys.extend_from_slice(session.list_objects_with_filter(
        0, ObjectType::PublicWrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?.as_slice());
    Ok(keys)
}

fn list(session: &Session) -> Result<(), MgmError> {
    list_objects(session, &get_wrap_keys(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_wrap_keys(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, get_all_wrap_key(session)?)
}

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
        .item(ObjectAlgorithm::Rsa2048, "RSA 2048", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa2048))
        .item(ObjectAlgorithm::Rsa3072, "RSA 3072", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa3072))
        .item(ObjectAlgorithm::Rsa4096, "RSA 4096", format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa4096))
        .interact()?;

    let mut new_key = get_new_object_basics(authkey, ObjectType::WrapKey, &AES_WRAP_KEY_CAPABILITIES, &[])?;
    let delegated = select_capabilities(
        "Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;
    new_key.delegated_capabilities = if delegated.is_empty() {None} else {Some(delegated)};

    cliclack::note("Generating wrap key with:",get_new_object_note(&new_key))?;

    if cliclack::confirm("Generate wrap key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating key...");
        new_key.id = session
            .generate_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice())?;
        spinner.stop("");
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
    let input:String = cliclack::input("Enter wrap key in HEX format or path to PEM file containing RSA key:").interact()?;
    let (key_type, key_bytes) = if let Ok(hex) = hex::decode(input.clone()) {
        cliclack::log::info("Detected HEX string. Parsing as AES wrap key...")?;
        let mut key = hex;
        loop {
            if key.len() == 16 || key.len() == 24 || key.len() == 32 {
                break;
            }
            cliclack::log::warning(format!("Provided key length is {} bytes, which is not valid for AES wrap key. Key must be 16, 24 or 32 bytes long", key.len()))?;
            let s:String = cliclack::input("Try again or press ESC to return to menu:").interact()?;
            key = hex::decode(s)?;
        }
        (WrapKeyType::Aes, key)
    } else if let Ok(pem) = read_pem_file(input.clone()) {
        let der_bytes = pem.contents();
        if let Ok(privkey) = openssl::pkey::PKey::private_key_from_der(der_bytes) {
            if privkey.id() != openssl::pkey::Id::RSA {
                return Err(MgmError::Error("Detected PEM file containing private key but is not an RSA private key".to_string()))
            }
            cliclack::log::info("Detected PEM file containing RSA private key. Parsing...")?;
            let private_rsa = privkey.rsa()?;
            let Some(p) = private_rsa.p() else {
                return Err(MgmError::InvalidInput("Failed to read p value".to_string()));
            };
            let Some(q) = private_rsa.q() else {
                return Err(MgmError::InvalidInput("Failed to read q value".to_string()));
            };
            let mut k = p.to_vec();
            k.extend_from_slice(&q.to_vec());
            (WrapKeyType::Rsa, k)
        } else if let Ok(pubkey) = openssl::pkey::PKey::public_key_from_der(der_bytes) {
            cliclack::log::info("Detected PEM file containing RSA public key. Parsing...")?;
            if pubkey.id() != openssl::pkey::Id::RSA {
                return Err(MgmError::Error("Detected PEM file containing public key but is not an RSA public key".to_string()))
            }
            (WrapKeyType::RsaPublic, pubkey.rsa()?.n().to_vec())
        } else {
            return Err(MgmError::Error("The provided PEM file does not contain a valid RSA key".to_string()))
        }
    } else {
        return Err(MgmError::InvalidInput("Input must be in HEX format or valid PEM file path".to_string()));
    };

    let algorithm = match key_bytes.len() {
        32 => ObjectAlgorithm::Aes256CcmWrap,
        24 => ObjectAlgorithm::Aes192CcmWrap,
        16 => ObjectAlgorithm::Aes128CcmWrap,
        256 => ObjectAlgorithm::Rsa2048,
        384 => ObjectAlgorithm::Rsa3072,
        512 => ObjectAlgorithm::Rsa4096,
        _ => return Err(MgmError::InvalidInput("Key length is not supported for AES or RSA wrap key".to_string())),
    };

    let caps = match key_type {
        WrapKeyType::Aes => &AES_WRAP_KEY_CAPABILITIES.to_vec(),
        WrapKeyType::Rsa => &RSA_WRAP_KEY_CAPABILITIES.to_vec(),
        WrapKeyType::RsaPublic => &PUBLIC_WRAP_KEY_CAPABILITIES.to_vec(),
    };

    let mut new_key = get_new_object_basics(authkey, ObjectType::WrapKey, caps, &[])?;
    let delegated = select_capabilities("Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;
    new_key.delegated_capabilities = if delegated.is_empty() {None} else {Some(delegated)};

    cliclack::note("Import wrap key with:", get_new_object_note(&new_key))?;

    let key_id = if cliclack::confirm("Import wrap key?").interact()? {
        match key_type {
            WrapKeyType::Aes | WrapKeyType::Rsa => session.import_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice(),
                &key_bytes)?,
            WrapKeyType::RsaPublic => session.import_public_wrap_key(
                new_key.id,
                &new_key.label,
                &new_key.domains,
                &new_key.capabilities,
                new_key.algorithm,
                get_delegated_capabilities(&new_key).as_slice(),
                &key_bytes)?,
        }
    } else {
        return Ok(());
    };

    cliclack::log::success(format!("Imported wrap key with ID 0x{:04x} on the device", key_id))?;

    if key_type == WrapKeyType::Aes && cliclack::confirm("Split wrap key? ").interact()? {
        // Split the wrap key
        let shares = get_shares()?;
        let threshold = get_threshold(shares)?;

        split_wrapkey(
            new_key.id,
            &new_key.domains,
            &new_key.capabilities,
            get_delegated_capabilities(&new_key).as_slice(),
            &key_bytes,
            threshold,
            shares,
        )?;
    }

    Ok(())
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let shares = recover_wrapkey_shares()?;
    let (mut new_key, key) = get_wrapkey_from_shares(shares)?;
    new_key.label = get_label()?;

    cliclack::note("Import wrap key with:", get_new_object_note(&new_key))?;

    if cliclack::confirm("Import wrap key?").interact()? {
        new_key.id = import_wrap_key(session, &new_key, &key)?;
        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

fn get_public_key(session: &Session) -> Result<(), MgmError> {
    let keys = session.
                          list_objects_with_filter(0, ObjectType::PublicWrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
    let key = select_one_object(
        "Select key" , convert_handlers(session, &keys)?)?;

    let pubkey = session.get_pubkey(key.id, ObjectType::PublicWrapKey)?;

    let key_algo = pubkey.1;
    if !RSA_KEY_ALGORITHM.contains(&key_algo) {
        return Err(MgmError::Error(format!("Object 0x{:04x} is not an RSA public wrap key", key.id)))
    }

    let e = BigNum::from_slice(&[0x01, 0x00, 0x01])?;
    let n = BigNum::from_slice(pubkey.0.as_slice())?;
    let pubkey = openssl::rsa::Rsa::from_public_components(n, e)?;
    let pubkey = pubkey.public_key_to_pem()?;

    if let Ok(str) = String::from_utf8(pubkey.clone()) { println!("{}\n", str) }

    if cliclack::confirm("Write to file?").interact()? {
        let filename = format!("0x{:04x}.pubkey.pem", key.id);
        if let Err(err) = write_bytes_to_file(pubkey, "", filename.as_str()) {
            cliclack::log::error(
                format!("Failed to write public key 0x{:04x} to file. {}", key.id, err))?;
        }
    }
    Ok(())
}

fn backup_device(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    if !authkey.capabilities.contains(&ObjectCapability::ExportWrapped) {
        return Err(MgmError::Error("Authentication key does not have the Export Under Wrap capability".to_string()))
    }

    let authkey_delegated = get_delegated_capabilities(authkey);

    let wrapkeys = get_all_wrap_key(session)?;
    let mut wrapkeys = convert_handlers(session, &wrapkeys)?;
    wrapkeys.retain(|k| {
        let t = get_wrapkey_type(k.object_type, k.algorithm);
        t == WrapKeyType::Aes || t == WrapKeyType::RsaPublic
    });
    let wrapping_key = select_one_object(
        "Select the wrapping key to use for exporting objects:",
        wrapkeys)?;
    let wrapkey_type = get_wrapkey_type(wrapping_key.object_type, wrapping_key.algorithm);
    let wrap_type = match wrapkey_type {
        WrapKeyType::Aes =>
            WrapType::Object,
        WrapKeyType::RsaPublic => {
            cliclack::select("Select type of wrapping:")
                .item(WrapType::Object, WrapType::Object, "")
                .item(WrapType::Key, WrapType::Key, "Available only for (a)symmetric keys")
                .interact()?
        }
        _ => unreachable!()
    };

    let exportable_objects = session.list_objects_with_filter(
        0,
        ObjectType::Any,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportableUnderWrap])?;
    let mut exportable_objects = convert_handlers(session, &exportable_objects)?;
    exportable_objects.retain(|k| contains_all(authkey_delegated.as_slice(), &k.capabilities));
    if wrap_type == WrapType::Key {
        exportable_objects.retain(|k| {
            k.object_type == ObjectType::SymmetricKey || k.object_type == ObjectType::AsymmetricKey
        });
    }
    cliclack::log::info(format!("Found {} objects marked as exportable-under-wrap", exportable_objects.len()))?;
    let export_objects = select_multiple_objects(
        "Select objects to export",
        exportable_objects, true)?;

    let dir: String = get_directory("Enter path to backup directory:")?;

    match wrapkey_type {
        WrapKeyType::Aes => {
            for object in export_objects {
                let format: u8 = if object.algorithm == ObjectAlgorithm::Ed25519  &&
                    cliclack::confirm("Object is an ED25519 key. If available, include seed in the export? (if not available, seed of value '0' will be included)").interact()? {
                    1
                } else {
                    0
                };
                match session.export_wrapped_ex(wrapping_key.id, object.object_type, object.id, format) {
                    Ok(bytes) => {
                        object_to_file(dir.clone(), object.id, object.object_type, &bytes)?;
                    }
                    Err(err) => cliclack::log::warning(format!(
                        "Unable to export {} object with ID 0x{:04x} wrapped under key ID 0x{:04x}: {}. Skipping over ...",
                        object.object_type, object.id, wrapping_key.id, err))?
                }
            }
        }
        WrapKeyType::RsaPublic => {
            do_rsa_wrap(session, wrapping_key.id, wrap_type, &export_objects, dir.clone())?;
        }
        _ => unreachable!()
    }
    Ok(())
}

fn restore_device(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrap_keys = session.list_objects_with_filter(
        0,
        ObjectType::WrapKey,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ImportWrapped])?;
    let wrapping_key = select_one_object(
        "Select the wrapping key to use for importing objects:",
        convert_handlers(session, &wrap_keys)?)?;
    let wrapkey_type = get_wrapkey_type(wrapping_key.object_type, wrapping_key.algorithm);

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

        let handle = match wrapkey_type {
            WrapKeyType::Aes => import_aes_unwrapped(session, wrapping_key.id, &data),
            WrapKeyType::Rsa => {
                let (_, oaep_algo, mgf1_algo, oaep_label) = get_rsa_wrap_algos(false)?;
                if let Ok(h) = import_rsa_unwrapped_object(session, wrapping_key.id, oaep_algo, mgf1_algo, oaep_label.clone(), &data) {
                    Ok(h)
                } else {
                    cliclack::log::info("Failed to unwrap as object, trying as key data...")?;
                    import_rsa_unwrapped_key(session, authkey, wrapping_key.clone(), oaep_algo, mgf1_algo, oaep_label, &data)
                }
            }
            _ => unreachable!()
        };

        match handle {
            Ok(h) => {
                cliclack::log::success(format!(
                    "Successfully imported object {}, with ID 0x{:04x}",
                    h.object_type, h.object_id))?;
            },
            Err(err) => {
                cliclack::log::warning(format!(
                    "Unable to import the content of file {}: {}. Skipping over ...",
                    f.display(),
                    err
                ))?;
                continue;
            }
        }
    }

    Ok(())
}

pub fn object_to_file(dir: String, id: u16, object_type: ObjectType, data: &[u8]) -> Result<String, MgmError> {
    let filename = format!("0x{:04x}-{}.yhw", id, object_type);
    write_bytes_to_file(base64::encode_block(data).as_bytes().to_vec(), &dir, filename.as_str())?;
    Ok(filename)
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

    for share in shares {
        loop {
            cliclack::clear_screen()?;
            cliclack::note("", share.clone())?;
            if cliclack::confirm("Have you saved the key share?").interact()? {
                break;
            }
        }
        cliclack::clear_screen()?;
        let _str: String = cliclack::input(
            "Press any key to display next key share or to return to menu").required(false).interact()?;

    }

    cliclack::clear_screen()?;
    Ok(())
}

fn recover_wrapkey_shares() -> Result<Vec<String>, MgmError> {

    let n_shares = get_shares()?;

    let mut shares_vec = Vec::new();
    let mut share_len = 0;

    while shares_vec.len() != n_shares as usize {
        cliclack::clear_screen()?;
        loop {
            let share: String = cliclack::input(format!("Enter share number {}:", shares_vec.len() + 1)).interact()?;
            if share_len == 0 && ([52,63,74].contains(&share.len())) {
                share_len = share.len();
            }

            if share.len() != share_len ||
                (!SHARE_RE_256.is_match(&share) && !SHARE_RE_192.is_match(&share) && !SHARE_RE_128.is_match(&share)) {
                cliclack::log::warning("Malformed share. Continuing...")?;
            } else {
                shares_vec.push(share);
                break;
            }
        }
        cliclack::clear_screen()?;
    }

    Ok(shares_vec)
}

pub fn get_shares() -> Result<u8, MgmError> {
    let n: String = cliclack::input("Enter the number of shares:")
        .placeholder("Must be greater than 0 and less than 256")
        .validate(|input: &String| {
            if input.parse::<u16>().is_err() {
                Err("Must be a positive number")
            } else if input.parse::<u16>().unwrap() == 0 || input.parse::<u16>().unwrap() > 0xFF {
                Err("Must be greater than zero and less than 256")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let n = n.parse::<u16>().unwrap();
    Ok(n as u8)
}

pub fn get_threshold(shares:u8) -> Result<u8, MgmError> {
    let n = shares as u16;
    let t: String = cliclack::input("Enter the number of shared necessary to re-create:")
        .placeholder(format!("Must be greater than 0 and less than {}", n).as_str())
        .validate(move |input: &String| {
            if input.parse::<u16>().is_err() {
                Err("Must be a positive number")
            } else if input.parse::<u16>().unwrap() == 0 || input.parse::<u16>().unwrap() > n {
                Err("Must be greater than zero and less than the number of shares")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let t = t.parse::<u16>().unwrap();

    if t == 1 {
        cliclack::log::warning("You have chosen a privacy threshold of one.\n\
                 The resulting share(s) will contain the unmodified raw wrap key in plain text.\n\
                 Make sure you understand the implications.")?;
        if !cliclack::confirm("Continue anyway?").interact()? {
            return  get_threshold(shares);
        }
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




fn get_wrapkey_type(object_type: ObjectType, algorithm: ObjectAlgorithm) -> WrapKeyType {
    match object_type {
        ObjectType::PublicWrapKey => WrapKeyType::RsaPublic,
        ObjectType::WrapKey => match algorithm {
            ObjectAlgorithm::Aes128CcmWrap |
            ObjectAlgorithm::Aes192CcmWrap |
            ObjectAlgorithm::Aes256CcmWrap => WrapKeyType::Aes,
            ObjectAlgorithm::Rsa2048 |
            ObjectAlgorithm::Rsa3072 |
            ObjectAlgorithm::Rsa4096 => WrapKeyType::Rsa,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

fn do_rsa_wrap(session: &Session, wrapkey_id: u16, wrap_type: WrapType, objects: &[ObjectDescriptor], destination_dir: String) -> Result<(), MgmError> {
    let (aes_algo, oaep_algo, mgf1_algo, oaep_label) = get_rsa_wrap_algos(true)?;

    for object in objects {
        let exported = match wrap_type {
            WrapType::Object => session.export_rsa_wrapped_object(
                wrapkey_id,
                object.object_type,
                object.id,
                aes_algo,
                oaep_algo,
                mgf1_algo,
                &oaep_label,
            ),
            WrapType::Key => session.export_rsa_wrapped_key(
                wrapkey_id,
                object.object_type,
                object.id,
                aes_algo,
                oaep_algo,
                mgf1_algo,
                &oaep_label,
            ),
        };

        match exported {
            Ok(bytes) => {
                object_to_file(destination_dir.clone(), object.id, object.object_type, &bytes)?;
            },
            Err(err) => {
                cliclack::log::warning(format!(
                    "Unable to export {} object with ID 0x{:04x} wrapped under key ID 0x{:04x}: {}. Skipping over ...",
                    object.object_type, object.id, wrapkey_id, err))?;
            }
        }
    }
    Ok(())
}

fn import_aes_unwrapped(session: &Session, wrapkey_id: u16, data: &[u8]) -> Result<ObjectHandle, MgmError> {
    let handle = session.import_wrapped(wrapkey_id, data)?;
    Ok(handle)
}

fn import_rsa_unwrapped_object(
    session: &Session,
    wrapkey_id: u16,
    oaep_algo: ObjectAlgorithm,
    mgf1_algo: ObjectAlgorithm,
    oaep_label: Vec<u8>,
    data: &[u8]) -> Result<ObjectHandle, MgmError> {
    let handle = session.import_rsa_wrapped_object(
        wrapkey_id,
        oaep_algo,
        mgf1_algo,
        oaep_label.as_slice(),
        data,
    )?;
    Ok(handle)
}

fn import_rsa_unwrapped_key(
    session: &Session,
    authkey: &ObjectDescriptor,
    wrapkey: ObjectDescriptor,
    oaep_algo: ObjectAlgorithm,
    mgf1_algo: ObjectAlgorithm,
    oaep_label: Vec<u8>,
    data: &[u8]) -> Result<ObjectHandle, MgmError> {

    let key_algo =
            cliclack::select("Select key algorithm")
                .item(ObjectAlgorithm::Rsa2048, ObjectAlgorithm::Rsa2048, format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa2048))
                .item(ObjectAlgorithm::Rsa3072, ObjectAlgorithm::Rsa3072, format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa3072))
                .item(ObjectAlgorithm::Rsa4096, ObjectAlgorithm::Rsa4096, format!("yubihsm-shell name: {}", ObjectAlgorithm::Rsa4096))
                .item(ObjectAlgorithm::EcK256, ObjectAlgorithm::EcK256, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcK256))
                .item(ObjectAlgorithm::EcP224, ObjectAlgorithm::EcP224, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcP224))
                .item(ObjectAlgorithm::EcP256, ObjectAlgorithm::EcP256, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcP256))
                .item(ObjectAlgorithm::EcP384, ObjectAlgorithm::EcP384, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcP384))
                .item(ObjectAlgorithm::EcP521, ObjectAlgorithm::EcP521, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcP521))
                .item(ObjectAlgorithm::EcBp256, ObjectAlgorithm::EcBp256, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcBp256))
                .item(ObjectAlgorithm::EcBp384, ObjectAlgorithm::EcBp384, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcBp384))
                .item(ObjectAlgorithm::EcBp512, ObjectAlgorithm::EcBp512, format!("yubihsm-shell name: {}", ObjectAlgorithm::EcBp512))
                .item(ObjectAlgorithm::Ed25519, ObjectAlgorithm::Ed25519, format!("yubihsm-shell name: {}", ObjectAlgorithm::Ed25519))
                .item(ObjectAlgorithm::Aes128, ObjectAlgorithm::Aes128, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes128))
                .item(ObjectAlgorithm::Aes192, ObjectAlgorithm::Aes192, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes192))
                .item(ObjectAlgorithm::Aes256, ObjectAlgorithm::Aes256, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes256))
                .interact()?;

    let (object_type, mut object_caps) = if [ObjectAlgorithm::Aes128, ObjectAlgorithm::Aes192, ObjectAlgorithm::Aes256].contains(&key_algo) {
        (ObjectType::SymmetricKey, AES_KEY_CAPABILITIES.to_vec())
    } else {
        let caps = if RSA_KEY_ALGORITHM.contains(&key_algo) {
            RSA_KEY_CAPABILITIES.to_vec()
        } else if EC_KEY_ALGORITHM.contains(&key_algo) {
            EC_KEY_CAPABILITIES.to_vec()
        } else if key_algo == ObjectAlgorithm::Ed25519 {
            ED_KEY_CAPABILITIES.to_vec()
        } else {
            unreachable!()
        };
        (ObjectType::AsymmetricKey, caps)
    };

    let wrapkey_delegated = get_delegated_capabilities(&wrapkey);
    object_caps.retain(|c| wrapkey_delegated.contains(c));
    let new_key = get_new_object_basics(
        authkey,
        object_type,
        &object_caps,
        &[],
    )?;

    let handle = session.import_rsa_wrapped_key(
        wrapkey.id,
        new_key.object_type,
        new_key.id,
        key_algo,
        &new_key.label,
        &new_key.domains,
        &new_key.capabilities,
        oaep_algo,
        mgf1_algo,
        oaep_label.as_slice(),
        data,
    )?;
    Ok(handle)
}


fn get_rsa_wrap_algos(include_aes: bool) -> Result<(ObjectAlgorithm, ObjectAlgorithm, ObjectAlgorithm, Vec<u8>), MgmError> {
    let aes_algo = if include_aes {
        cliclack::select("Select AES algorithm")
            .initial_value(ObjectAlgorithm::Aes256)
            .item(ObjectAlgorithm::Aes128, ObjectAlgorithm::Aes128, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes128))
            .item(ObjectAlgorithm::Aes192, ObjectAlgorithm::Aes192, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes192))
            .item(ObjectAlgorithm::Aes256, ObjectAlgorithm::Aes256, format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes256))
            .interact()?
        } else {
            ObjectAlgorithm::ANY
        };

    let oaep_algo = cliclack::select("Select OAEP hash algorithm")
        .item(ObjectAlgorithm::RsaOaepSha1, ObjectAlgorithm::RsaOaepSha1, format!("yubihsm-shell name: {}", ObjectAlgorithm::RsaOaepSha1))
        .item(ObjectAlgorithm::RsaOaepSha256, ObjectAlgorithm::RsaOaepSha256, format!("yubihsm-shell name: {}", ObjectAlgorithm::RsaOaepSha256))
        .item(ObjectAlgorithm::RsaOaepSha384, ObjectAlgorithm::RsaOaepSha384, format!("yubihsm-shell name: {}", ObjectAlgorithm::RsaOaepSha384))
        .item(ObjectAlgorithm::RsaOaepSha512, ObjectAlgorithm::RsaOaepSha512, format!("yubihsm-shell name: {}", ObjectAlgorithm::RsaOaepSha512))
        .interact()?;

    let mgf1_algo = cliclack::select("Select MGF1 hash algorithm")
        .item(ObjectAlgorithm::Mgf1Sha1, ObjectAlgorithm::Mgf1Sha1, format!("yubihsm-shell name: {}", ObjectAlgorithm::Mgf1Sha1))
        .item(ObjectAlgorithm::Mgf1Sha256, ObjectAlgorithm::Mgf1Sha256, format!("yubihsm-shell name: {}", ObjectAlgorithm::Mgf1Sha256))
        .item(ObjectAlgorithm::Mgf1Sha384, ObjectAlgorithm::Mgf1Sha384, format!("yubihsm-shell name: {}", ObjectAlgorithm::Mgf1Sha384))
        .item(ObjectAlgorithm::Mgf1Sha512, ObjectAlgorithm::Mgf1Sha512, format!("yubihsm-shell name: {}", ObjectAlgorithm::Mgf1Sha512))
        .interact()?;

    let oaep_label:&[u8;64] = &[0;64];
    let oaep_label = get_hashed_bytes(&oaep_algo, oaep_label)?;
    Ok((aes_algo, oaep_algo, mgf1_algo, oaep_label))
}