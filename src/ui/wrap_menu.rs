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

use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::backend_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::{asym_menu, device_menu};
use crate::ui::utils::{display_menu_headers, write_bytes_to_file, delete_objects, display_object_properties, get_pem_from_file};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::types::{SelectionItem, MgmCommandType, ImportObjectSpec, ObjectSpec};
use crate::backend::validators::{aes_key_validator, pem_private_rsa_file_validator, pem_public_rsa_file_validator};
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::asym::AsymOps;
use crate::backend::sym::SymOps;
use crate::backend::wrap::{WrapOps, WrapOpSpec, WrapType, WrapKeyType};
use crate::backend::common::get_delegated_capabilities;

static WRAP_HEADER: &str = "Wrap keys";

pub fn exec_wrap_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        display_menu_headers(&[crate::MAIN_HEADER, WRAP_HEADER],
                             "Wrap key operations allow you to manage and use wrap keys keys stored on the YubiHSM")?;

        let cmd = YubihsmUi::select_command(&Cmdline, &WrapOps.get_authorized_commands(authkey))?;
        display_menu_headers(&[crate::MAIN_HEADER, WRAP_HEADER, cmd.label], cmd.description)?;

        let result = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => print_key_properties(session),
            MgmCommandType::Generate => generate(session, authkey),
            MgmCommandType::Import => import(session, authkey),
            MgmCommandType::Delete => delete(session),
            MgmCommandType::GetPublicKey => asym_menu::get_public_key(session, ObjectType::WrapKey),
            MgmCommandType::ExportWrapped => export_wrapped(session, authkey),
            MgmCommandType::ImportWrapped => import_wrapped(session, authkey),
            MgmCommandType::GetRandom => device_menu::get_random(session),
            MgmCommandType::ReturnToMainMenu => return Ok(()),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(err) = result {
            YubihsmUi::display_error_message(&Cmdline, err.to_string().as_str())?;
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    YubihsmUi::display_objects_basic(&Cmdline, &WrapOps.get_all_objects(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&WrapOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, &WrapOps.get_all_objects(session)?)
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = ObjectSpec::empty();
    new_key.object_type = ObjectType::WrapKey;
    new_key.algorithm = YubihsmUi::select_algorithm(
        &Cmdline,
        &WrapOps.get_generation_algorithms(),
        None,
        Some("Select wrap key algorithm"))?;

    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &WrapOps.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
        &[],
        None)?;
    new_key.delegated_capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &get_delegated_capabilities(authkey),
        &get_delegated_capabilities(authkey),
        Some("Select delegated capabilities"))?;

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Generating wrap key with:", &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Key is not generated")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.id = WrapOps.generate(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Generated wrap key with ID 0x{:04x} on the YubiHSM", new_key.id).as_str())?;
    Ok(())
}

pub fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    if YubihsmUi::get_confirmation(&Cmdline, "Re-create from shares?")? {
        import_from_shares(session)
    } else {
        import_full_key(session, authkey)
    }
}

fn import_full_key(session:&Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = ImportObjectSpec::empty();


    let mut input = YubihsmUi::get_string_input(
        &Cmdline, "Enter wrap key in HEX format or path to PEM file containing RSA key:", true)?;
    loop {
        if aes_key_validator(&input).is_ok() || pem_private_rsa_file_validator(&input).is_ok() || pem_public_rsa_file_validator(&input).is_ok() {
            break;
        }
        YubihsmUi::display_error_message(&Cmdline, "Input is neither valid AES key in HEX format nor valid path to a file containing RSA key in PEM format")?;
        input = YubihsmUi::get_string_input(
            &Cmdline, "Try again or press ESC to return to menu:", true)?;
    }

    if aes_key_validator(&input).is_ok() {
        YubihsmUi::display_info_message(&Cmdline,"Detected HEX string. Parsing as AES wrap key...")?;
        new_key.object.object_type = ObjectType::WrapKey;
        new_key.data.push(hex::decode(input)?);
        new_key.object.algorithm = WrapOps::get_algorithm_from_keylen(new_key.data[0].len())?;
    } else if pem_private_rsa_file_validator(&input).is_ok() || pem_public_rsa_file_validator(&input).is_ok() {
        YubihsmUi::display_info_message(&Cmdline, "Detected PEM file with private RSA key. Parsing as RSA key...")?;
        let pem = get_pem_from_file(&input)?[0].clone();
        let (_type, _algo, _bytes) = AsymOps::parse_asym_pem(pem)?;
        new_key.data.push(_bytes);
        new_key.object.algorithm = _algo;
        match _type {
            ObjectType::AsymmetricKey => new_key.object.object_type = ObjectType::WrapKey,
            ObjectType::PublicKey => new_key.object.object_type = ObjectType::PublicWrapKey,
            _ => unreachable!()
        }
    } else {
        unreachable!();
    }
    let key_type = WrapOps::get_wrapkey_type(new_key.object.object_type, new_key.object.algorithm)?;

    new_key.object.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.object.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.object.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.object.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &WrapOps.get_applicable_capabilities(authkey, Some(new_key.object.object_type), Some(new_key.object.algorithm))?,
        &[],
        Some("Select object capabilities"))?;
    new_key.object.delegated_capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &get_delegated_capabilities(authkey),
        &get_delegated_capabilities(authkey),
        Some("Select delegated capabilities"))?;

    if !YubihsmUi::get_note_confirmation(
        &Cmdline,
        "Import wrap key with:",
        &new_key.object.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Object is not imported")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.object.id = WrapOps.import(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object.object_type, new_key.object.id).as_str())?;


    if key_type != WrapKeyType::Aes {
        return Ok(());
    }

    YubihsmUi::display_info_message(&Cmdline, "Split wrap key? Note that the wrap key is already imported into the YubiHSM2. Key split is done outside the device")?;
    if YubihsmUi::get_confirmation(&Cmdline, "Split wrap key?")? {
        let n_shares = YubihsmUi::get_split_aes_n_shares(&Cmdline, "Enter the number of shares to create:")?;
        let n_threshold = YubihsmUi::get_split_aes_m_threshold(&Cmdline, "Enter the number of shares necessary to re-create the key:", n_shares)?;
        let split_key = WrapOps::split_wrap_key(&new_key, n_threshold, n_shares)?;
        display_wrapkey_shares(split_key.shares_data)?;
    }

    Ok(())
}

fn import_from_shares(session:&Session) -> Result<(), MgmError> {
    let shares = recover_wrapkey_shares()?;
    let mut new_key = WrapOps::get_wrapkey_from_shares(shares)?;
    new_key.object.label = YubihsmUi::get_object_label(&Cmdline, "")?;

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Import wrap key with:", new_key.object.to_string().as_str())? {
        YubihsmUi::display_info_message(&Cmdline, "Key is not imported")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Importing key..."));
    new_key.object.id = WrapOps.import(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);

    YubihsmUi::display_success_message(&Cmdline,
            format!("Imported wrap key with ID 0x{:04x} on the device", new_key.object.id).as_str())?;
    Ok(())
}

fn export_wrapped(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_wrapping_keys(session, authkey)?;
    let wrapkey = YubihsmUi::select_one_object(
         &Cmdline,
         &wrapkeys,
        Some("Select the wrapping key to use for exporting objects:"))?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

    let wrap_type = match wrapkey_type {
        WrapKeyType::Aes =>
            WrapType::Object,
        WrapKeyType::RsaPublic => {
            YubihsmUi::select_one_item(
                &Cmdline,
                &SelectionItem::get_items(&[WrapType::Object, WrapType::Key]),
                Some(&WrapType::Object),
                Some("Select type of wrapping:"))?
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
    let export_objects = YubihsmUi::select_multiple_objects(
        &Cmdline,
        &exportable_objects,
        false,
        Some("Select objects to export"))?;
    if exportable_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
        wrap_op.include_ed_seed = YubihsmUi::get_confirmation(&Cmdline, "Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)")?;
    };

    if wrapkey_type == WrapKeyType::RsaPublic {
        wrap_op.aes_algorithm = Some(YubihsmUi::select_algorithm(
            &Cmdline,
            &SymOps.get_generation_algorithms(),
            Some(ObjectAlgorithm::Aes256),
            Some("Select AES algorithm to use for wrapping"))?);
        wrap_op.oaep_algorithm = Some(YubihsmUi::select_algorithm(
            &Cmdline,
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS,
            Some(ObjectAlgorithm::RsaOaepSha256),
            Some("Select OAEP algorithm to use for wrapping"))?);
    }

    let dir = YubihsmUi::get_path_input(
        &Cmdline,
        "Enter path to backup directory:",
        false,
        Some("."),
        Some("Default is current directory"))?;

    let wrapped_objects = WrapOps::export_wrapped(session, &wrap_op, &export_objects)?;

    for object in &wrapped_objects {
        if object.error.is_some() {
            YubihsmUi::display_warning(&Cmdline, format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()).as_str())?;
            continue;
        }
        let filename = format!("0x{:04x}-{}.yhw", object.object_id, object.object_type);
        write_bytes_to_file(base64::encode_block(&object.wrapped_data).as_bytes(), filename.as_str(), Some(&dir))?;
    }

    Ok(())
}

fn import_wrapped(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let filepath = YubihsmUi::get_path_input(
        &Cmdline,
        "Enter absolute path to wrapped object file:",
        true,
        None,
        Some("Files containing wrapped YubiHSM objects usually have the file extension .yhw"))?;

    let mut file = File::open(&filepath)?;

    let mut wrapped = String::new();
    file.read_to_string(&mut wrapped)?;
    if wrapped.is_empty() {
        return Err(MgmError::Error(format!("File {} is empty", filepath)));
    }
    // let data = base64::decode_block(&wrapped)?;

    let wrapkeys = WrapOps::get_unwrapping_keys(session, authkey)?;
    let wrapkey = YubihsmUi::select_one_object(
        &Cmdline,
        &wrapkeys,
        Some("Select the unwrapping key to use for importing objects:"))?;
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
        wrap_op.oaep_algorithm = Some(YubihsmUi::select_algorithm(
            &Cmdline,
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS,
            Some(ObjectAlgorithm::RsaOaepSha256),
            Some("Select OAEP algorithm to use for wrapping"))?);
    }

    let res = WrapOps::import_wrapped(session, &wrap_op, wrapped.clone(), None);
    let handle = match res {
        Ok(h) => h,
        Err(e) => {
            if wrapkey_type == WrapKeyType::Rsa {
                YubihsmUi::display_info_message(&Cmdline, "Failed to unwrap as object, trying as key data...")?;

                let algo = YubihsmUi::select_algorithm(
                    &Cmdline,
                    &WrapOps::get_unwrapped_key_algorithms(),
                    None,
                    Some("Select wrapped key algorithm"))?;
                let caps = if SymOps::is_aes_algorithm(&algo) {
                    SymOps.get_applicable_capabilities(&wrapkey, None, None)?
                } else {
                    AsymOps.get_applicable_capabilities(&wrapkey, None, Some(algo))?
                };

                let mut new_key = ObjectSpec::empty();
                new_key.algorithm = algo;
                new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
                new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
                new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
                new_key.capabilities = YubihsmUi::select_object_capabilities(
                    &Cmdline,
                    &caps,
                    &[],
                    Some("Select object capabilities"))?;

                WrapOps::import_wrapped(session, &wrap_op, wrapped, Some(new_key))?
            } else {
                return Err(e)
            }
        }
    };

    YubihsmUi::display_success_message(&Cmdline, format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id).as_str())?;

    Ok(())
}

pub fn display_wrapkey_shares(shares:Vec<String>) -> Result<(), MgmError> {

    YubihsmUi::display_warning(&Cmdline,
        "*************************************************************\n\
        * WARNING! The following shares will NOT be stored anywhere *\n\
        * Save them and store them safely if you wish to re-use   *\n\
        * the wrap key for this device in the future                *\n\
        *************************************************************")?;

    YubihsmUi::get_string_input(&Cmdline, "Press Enter to start saving key shares", false)?;

    for share in shares {
        loop {
            YubihsmUi::clear_screen(&Cmdline)?;
            YubihsmUi::display_note(&Cmdline,   "", &share)?;
            if YubihsmUi::get_confirmation(&Cmdline, "Have you saved the key share?")? {
                break;
            }
        }
        YubihsmUi::clear_screen(&Cmdline)?;
        YubihsmUi::get_string_input(&Cmdline,
            "Press any key to display next key share or to return to menu", false)?;
    }

    YubihsmUi::clear_screen(&Cmdline)?;
    Ok(())
}

fn recover_wrapkey_shares() -> Result<Vec<String>, MgmError> {

    YubihsmUi::display_warning(&Cmdline, "Note that the wrap key will be recreated outside the YubiHSM before importing it in its whole into the device")?;
    YubihsmUi::get_string_input(&Cmdline,
                                "Press any key to recreate wrap key from shares", false)?;

    let n_shares = YubihsmUi::get_split_aes_n_shares(
        &Cmdline, "Enter the number of shares to re-create the AES wrap key:")?;
    let mut shares_vec = Vec::new();

    YubihsmUi::clear_screen(&Cmdline)?;
    shares_vec.push(YubihsmUi::get_split_aes_share(&Cmdline, "Enter share number 1:", None)?);

    if n_shares > 1 {
        for i in 2..=n_shares {
            YubihsmUi::clear_screen(&Cmdline)?;
            shares_vec.push(YubihsmUi::get_split_aes_share(&Cmdline, format!("Enter share number {}:", i).as_str(), Some(shares_vec[0].len() as u8))?);
        }
    }
    YubihsmUi::clear_screen(&Cmdline)?;

    YubihsmUi::display_info_message(&Cmdline, format!("{} shares have been registered", n_shares).as_str())?;

    Ok(shares_vec)
}
