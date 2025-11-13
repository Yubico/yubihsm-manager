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

use std::fs::File;
use std::io::Read;

use std::sync::LazyLock;
use regex::Regex;
use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::algorithms::MgmAlgorithm;
use crate::ui::cmd_utils::{fill_object_spec, get_id, get_label, print_failed_delete, print_menu_headers, print_object_properties, select_algorithm, select_capabilities, select_delete_objects, select_domains, select_multiple_objects};
use crate::backend::types::YhCommand;
use crate::ui::cmd_utils::select_command;
use crate::backend::wrap::WrapKeyType;
use crate::ui::asym_menu;
use crate::backend::asym::AsymOps;
use crate::backend::object_ops::Importable;
use crate::backend::sym::SymOps;
use crate::backend::types::ImportObjectSpec;
use crate::backend::wrap::{WrapOpSpec, WrapType};
use crate::ui::cmd_utils::select_one_object;
use crate::ui::io_utils::read_pem_from_file;
use crate::backend::object_ops::{Deletable, Generatable, Obtainable};
use crate::backend::types::ObjectSpec;
use crate::backend::wrap::WrapOps;
use crate::ui::cmd_utils::list_objects;
use crate::backend::error::MgmError;
use crate::ui::io_utils::{get_directory, get_file_path, write_bytes_to_file};
use crate::backend::common::get_delegated_capabilities;

static WRAP_HEADER: &str = "Wrap keys";

static SHARE_RE_256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap());
static SHARE_RE_192: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap());
static SHARE_RE_128: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap());

pub fn exec_wrap_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        print_menu_headers(&[crate::MAIN_HEADER, WRAP_HEADER]);

        let cmd = select_command(&WrapOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, WRAP_HEADER, cmd.label]);

        let result = match cmd.command {
            YhCommand::List => list(session),
            YhCommand::GetKeyProperties => print_key_properties(session),
            YhCommand::Generate => generate(session, authkey),
            YhCommand::Import => import(session, authkey),
            YhCommand::Delete => delete(session),
            YhCommand::GetPublicKey => asym_menu::get_public_key(session, ObjectType::WrapKey),
            YhCommand::ExportWrapped => export_wrapped(session, authkey),
            YhCommand::ImportWrapped => import_wrapped(session, authkey),
            YhCommand::BackupDevice => backup(session, authkey),
            YhCommand::RestoreDevice => restore(session, authkey),
            YhCommand::ReturnToMainMenu => return Ok(()),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(err) = result {
            cliclack::log::error(err)?;
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    list_objects(&WrapOps.get_all_objects(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(&WrapOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(&WrapOps.get_all_objects(session)?)?;
    let failed = WrapOps.delete_multiple(session, &objects);
    print_failed_delete(&failed)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = ObjectSpec::empty();
    let key_algo = select_algorithm("Select wrap key algorithm", &WrapOps::get_object_algorithms(), None)?;
    let key_type = if AsymOps::is_rsa_key_algorithm(&key_algo) { WrapKeyType::Rsa } else { WrapKeyType::Aes };
    new_key.algorithm = key_algo;
    fill_object_spec(authkey, &mut new_key, &WrapOps::get_wrapkey_capabilities(key_type), &[])?;
    new_key.delegated_capabilities = select_capabilities(
        "Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;


    cliclack::note("Generating wrap key with:",new_key.to_string())?;
    if cliclack::confirm("Generate wrap key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating key...");
        new_key.id = WrapOps.generate(session, &new_key)?;
        cliclack::log::success(
            format!("Generated wrap key with ID 0x{:04x} on the device", new_key.id))?;
        spinner.stop("");
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
    let (key_type, key_algo, key_bytes) = if let Ok(hex) = hex::decode(input.clone()) {
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
        let algo = match key.len() {
            16 => ObjectAlgorithm::Aes128CcmWrap,
            24 => ObjectAlgorithm::Aes192CcmWrap,
            32 => ObjectAlgorithm::Aes256CcmWrap,
            _ => unreachable!(),
        };
        (WrapKeyType::Aes, algo, key)
    } else if let Ok(pem) = read_pem_from_file(input.clone()) {
        cliclack::log::info("Detected PEM file. Parsing as RSA key...")?;

        let mut p = pem;
        let parsed;
        loop {
            let res = AsymOps::parse_asym_pem(p.clone());
            if let Ok(items) = res {
                if AsymOps::is_rsa_key_algorithm(&items.1) {
                    parsed = items;
                    break;
                }
            }
            cliclack::log::warning("Provided PEM file does not contain a valid RSA wrap key. Only private or public RSA keys of length 2048, 3072, 4096 are valid".to_string())?;
            let filepath:String = cliclack::input("Try again or press ESC to return to menu:").interact()?;
            p = read_pem_from_file(filepath)?;
        }

        let (_type, _algo, _bytes) = parsed;
        match _type {
            ObjectType::AsymmetricKey => {
                (WrapKeyType::Rsa, _algo, _bytes)
            },
            ObjectType::PublicKey => {
                (WrapKeyType::RsaPublic, _algo, _bytes)
            },
            _ => unreachable!()
        }
    } else {
        return Err(MgmError::InvalidInput("Input must be in HEX format or valid PEM file path".to_string()));
    };

    let mut spec = ImportObjectSpec::empty();
    spec.object.object_type = if key_type == WrapKeyType::RsaPublic {ObjectType::PublicWrapKey} else {ObjectType::WrapKey};
    spec.object.algorithm = key_algo;
    spec.data.push(key_bytes);
    fill_object_spec(authkey, &mut spec.object, &WrapOps::get_wrapkey_capabilities(key_type), &[])?;
    spec.object.delegated_capabilities = select_capabilities("Select delegated capabilities", authkey, get_delegated_capabilities(authkey).as_slice(), get_delegated_capabilities(authkey).as_slice())?;

    cliclack::note("Import wrap key with:", spec.object.to_string())?;

    if cliclack::confirm("Import wrap key?").interact()? {
        spec.object.id = WrapOps.import(session, &spec)?;
        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", spec.object.id))?;
    } else {
        return Ok(());
    }

    cliclack::log::remark("Split wrap key? Note that the wrap key is already imported into the YubiHSM2. Key split is done outside the device")?;
    if key_type == WrapKeyType::Aes && cliclack::confirm("Split wrap key?").interact()? {
        let n_shares = get_shares()?;
        let n_threshold = get_threshold(n_shares)?;
        let split_key = WrapOps::split_wrap_key(&spec, n_threshold, n_shares)?;
        display_wrapkey_shares(split_key.shares_data)?;
    }

    Ok(())
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let shares = recover_wrapkey_shares()?;
    let mut key_spec = WrapOps::get_wrapkey_from_shares(shares)?;
    key_spec.object.label = get_label()?;

    cliclack::note("Import wrap key with:", key_spec.object.to_string())?;

    if cliclack::confirm("Import wrap key?").interact()? {
        key_spec.object.id = WrapOps.import(session, &key_spec)?;
        cliclack::log::success(
            format!("Imported wrap key with ID 0x{:04x} on the device", key_spec.object.id))?;
    }
    Ok(())
}

fn export_wrapped(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_wrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the wrapping key to use for exporting objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

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
    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };

    let exportable_objects = WrapOps::get_exportable_objects(session, &wrapkey, wrap_type)?;
    let export_objects = select_multiple_objects(
        "Select objects to export",
        &exportable_objects, false)?;
    if exportable_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
        wrap_op.include_ed_seed = cliclack::confirm("Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)").interact()?
    };

    if wrapkey_type == WrapKeyType::RsaPublic {
        wrap_op.aes_algorithm = Some(select_algorithm(
            "Select AES algorithm to use for wrapping",
            &SymOps::get_object_algorithms(), Some(ObjectAlgorithm::Aes256))?);
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for wrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    let dir: String = get_directory("Enter path to backup directory:")?;

    let wrapped_objects = WrapOps::export_wrapped(session, &wrap_op, &export_objects)?;

    for object in &wrapped_objects {
        if object.error.is_some() {
            cliclack::log::warning(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()))?;
            continue;
        }
        let filename = format!("0x{:04x}-{}.yhw", object.object_id, object.object_type);
        // utils::write_object_to_file(&dir, object.object_id, object.object_type, &object.wrapped_data)?;
        write_bytes_to_file(base64::encode_block(&object.wrapped_data).as_bytes(), &dir, filename.as_str())?;
    }

    Ok(())
}

fn import_wrapped(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let filepath = get_file_path("Enter absolute path to wrapped object file:")?;
    let mut file = File::open(&filepath)?;

    let mut wrapped = String::new();
    file.read_to_string(&mut wrapped)?;
    if wrapped.is_empty() {
        return Err(MgmError::Error(format!("File {} is empty", filepath)));
    }
    // let data = base64::decode_block(&wrapped)?;

    let wrapkeys = WrapOps::get_unwrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the unwrapping key to use for importing objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };
    if wrapkey_type == WrapKeyType::Rsa {
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for wrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    let res = WrapOps::import_wrapped(session, &wrap_op, wrapped.clone(), None);
    let handle = match res {
        Ok(h) => h,
        Err(e) => {
            if wrapkey_type == WrapKeyType::Rsa {
                cliclack::log::info("Failed to unwrap as object, trying as key data...")?;

                let algo = select_algorithm("Select wrapped key algorithm", &WrapOps::get_unwrapped_key_algorithms(), None)?;
                let caps = if SymOps::is_aes_algorithm(&algo) {
                    SymOps::get_object_capabilities(&algo)
                } else {
                    AsymOps::get_object_capabilities(&algo)
                };

                let mut new_key = ObjectSpec::empty();
                new_key.algorithm = algo;
                new_key.id = get_id()?;
                new_key.label = get_label()?;
                new_key.domains = select_domains(&authkey.domains)?;
                new_key.capabilities = select_capabilities(
                    "Select object capabilities", &wrapkey, &caps, &[])?;

                WrapOps::import_wrapped(session, &wrap_op, wrapped, Some(new_key))?
            } else {
                return Err(e)
            }
        }
    };

    cliclack::log::success(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id))?;

    Ok(())
}



fn backup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_wrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the wrapping key to use for exporting objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };

    let export_objects = WrapOps::get_exportable_objects(session, &wrapkey, WrapType::Object)?;
    if export_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
        wrap_op.include_ed_seed = cliclack::confirm("Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)").interact()?
    };

    if wrapkey_type == WrapKeyType::RsaPublic {
        wrap_op.aes_algorithm = Some(select_algorithm(
            "Select AES algorithm to use for wrapping",
            &SymOps::get_object_algorithms(), Some(ObjectAlgorithm::Aes256))?);
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for wrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    let dir: String = get_directory("Enter path to backup directory:")?;

    let wrapped_objects = WrapOps::export_wrapped(session, &wrap_op, &export_objects)?;

    for object in &wrapped_objects {
        if object.error.is_some() {
            cliclack::log::warning(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()))?;
            continue;
        }
        let filename = format!("0x{:04x}-{}.yhw", object.object_id, object.object_type);
        write_bytes_to_file(base64::encode_block(&object.wrapped_data).as_bytes(), &dir, filename.as_str())?;
    }

    Ok(())
}

fn restore(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_unwrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the unwrapping key to use for importing objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

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

    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };
    if wrapkey_type == WrapKeyType::Rsa {
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for unwrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    for f in files {
        cliclack::log::info(format!("reading {}", &f.display()))?;
        let mut file = File::open(&f)?;

        let mut wrap = String::new();
        file.read_to_string(&mut wrap)?;

        let res = WrapOps::import_wrapped(session, &wrap_op, wrap, None);
        match res {
            Ok(handle) => {
                cliclack::log::success(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id))?;
            },
            Err(e) => {
                cliclack::log::error(format!("Failed to import wrapped object from file {}: {}. Skipping...", f.display(), e))?;
            }
        }
    }
    Ok(())
}

pub fn display_wrapkey_shares(shares:Vec<String>) -> Result<(), MgmError> {

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

    Ok(t as u8)
}