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

use yubihsmrs::object::{ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::backend_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::utils::{display_menu_headers, write_bytes_to_file, delete_objects, display_object_properties, get_hex_or_bytes_from_file};
use crate::ui::device_menu;
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::types::{MgmCommandType, NewObjectSpec, SelectionItem};
use crate::backend::sym::{SymOps, AesMode, EncryptionMode, AesOperationSpec};

static SYM_HEADER: &str = "Symmetric keys";

pub fn exec_sym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {
        display_menu_headers(&[crate::MAIN_HEADER, SYM_HEADER],
                             "Symmetric key operations allow you to manage and use symmetric keys stored on the YubiHSM")?;

        let cmd = YubihsmUi::select_command(&Cmdline, &SymOps.get_authorized_commands(authkey))?;
        display_menu_headers(&[crate::MAIN_HEADER, SYM_HEADER, cmd.label], cmd.description)?;

        let res = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => print_key_properties(session),
            MgmCommandType::Generate => generate(session, authkey),
            MgmCommandType::Import => import(session, authkey),
            MgmCommandType::Delete => delete(session),
            MgmCommandType::Encrypt => operate(session, authkey, EncryptionMode::Encrypt),
            MgmCommandType::Decrypt => operate(session, authkey, EncryptionMode::Decrypt),
            MgmCommandType::GetRandom => device_menu::get_random(session),
            MgmCommandType::ReturnToMainMenu => return Ok(()),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = SymOps.get_all_objects(session)?;
    YubihsmUi::display_objects_basic(&Cmdline, &keys)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&SymOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, &SymOps.get_all_objects(session)?)
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = ObjectType::SymmetricKey;
    new_key.algorithm = YubihsmUi::select_algorithm(
        &Cmdline,
        &SymOps.get_generation_algorithms(),
        None,
        Some("Select AES key algorithm:"))?;
    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &SymOps.get_applicable_capabilities(authkey, None, None)?,
        &[],
        None)?;

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Generating symmetric key with:", &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Key is not generated")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.id = SymOps.generate(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Generated symmetric key with ID 0x{:04x} on the YubiHSM", new_key.id).as_str())?;
    Ok(())
}

pub fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = ObjectType::SymmetricKey;
    new_key.data.push(YubihsmUi::get_aes_key_hex(&Cmdline, "Enter AES key in HEX format:")?);
    new_key.algorithm = SymOps::get_symkey_algorithm_from_keylen(new_key.data[0].len())?;
    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &SymOps.get_applicable_capabilities(authkey, None, None)?,
        &[],
        None)?;

    if !YubihsmUi::get_note_confirmation(
        &Cmdline,
        "Importing symmetric object with:",
        &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Object is not imported")?;
        return Ok(());
    }

    new_key.id = SymOps.import(session, &new_key)?;
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Imported symmetric key with ID 0x{:04x} into the YubiHSM", new_key.id).as_str())?;
    Ok(())}

fn operate(session: &Session, authkey: &ObjectDescriptor, enc_mode: EncryptionMode) -> Result<(), MgmError> {
    let mut aes_mode = vec![];
    if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptEcb)) ||
        (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptEcb)) {
        aes_mode.push(SelectionItem::new(AesMode::Ecb, "ECB".to_string(),"".to_string()));
    }
    if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptCbc)) ||
        (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptCbc)) {
        aes_mode.push(SelectionItem::new(AesMode::Cbc, "CBC".to_string(),"".to_string()));
    }
    let aes_mode = YubihsmUi::select_one_item(
        &Cmdline,
        &aes_mode,
        None,
        Some("Select AES encryption mode:"))?;

    let key = YubihsmUi::select_one_object(&Cmdline,
        &SymOps::get_operation_keys(session, authkey, enc_mode, aes_mode)?, Some("Select AES key for operation:"))?;


    let in_data = YubihsmUi::get_string_input(
        &Cmdline, "Enter data in hex or absolut path to binary file (data must be a multiple of 16 bytes long):", true)?;
    let in_data = get_hex_or_bytes_from_file(in_data)?;
    if in_data.len() % 16 != 0 {
        return Err(MgmError::InvalidInput("Input data must be a multiple of 16 bytes".to_string()))
    }

    let iv = if aes_mode == AesMode::Cbc {
        YubihsmUi::get_aes_iv_hex(&Cmdline, "Enter 16 bytes IV in HEX format:", false, Some("00000000000000000000000000000000"))?
    } else {
        vec![]
    };

    let op_spec = AesOperationSpec {
        operation_key: key,
        aes_mode,
        enc_mode,
        iv,
        data: in_data,
    };
    let out_data = SymOps::operate(session, op_spec)?;

    YubihsmUi::display_success_message(&Cmdline, hex::encode(&out_data).as_str())?;

    if YubihsmUi::get_confirmation(&Cmdline, "Write to binary file?")? {
        let filename = if enc_mode == EncryptionMode::Encrypt {"data.enc"} else {"data.dec"};
        if let Err(err) = write_bytes_to_file(&out_data, filename, None) {
            YubihsmUi::display_error_message(&Cmdline, format!("Failed to write binary data to file. {}", err).as_str())?;
        }
    }

    Ok(())
}