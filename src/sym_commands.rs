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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::common::get_new_object_note;
use crate::utils::{delete_objects, get_new_object_basics, get_operation_key, list_objects, print_object_properties, read_input_bytes,
                   write_bytes_to_file, select_delete_objects, fill_new_object_properties, read_aes_key_hex};
use crate::backend::sym_utils::{AesMode, EncryptionMode, get_sym_keys, get_algorithm_from_keylen};
use crate::error::MgmError;
use crate::MAIN_STRING;

static SYM_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > Symmetric keys", MAIN_STRING));

pub const AES_KEY_CAPABILITIES: [ObjectCapability; 5] = [
    ObjectCapability::EncryptCbc,
    ObjectCapability::DecryptCbc,
    ObjectCapability::EncryptEcb,
    ObjectCapability::DecryptEcb,
    ObjectCapability::ExportableUnderWrap];

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
enum SymCommand {
    #[default]
    List,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    Encrypt,
    Decrypt,
    ReturnToMainMenu,
    Exit,
}

impl Display for SymCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SymCommand::List => write!(f, "List"),
            SymCommand::GetKeyProperties => write!(f, "Print object properties"),
            SymCommand::Generate => write!(f, "Generate"),
            SymCommand::Import => write!(f, "Import"),
            SymCommand::Delete => write!(f, "Delete"),
            SymCommand::Encrypt => write!(f, "Encrypt"),
            SymCommand::Decrypt => write!(f, "Decrypt"),
            SymCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            SymCommand::Exit => write!(f, "Exit"),
        }
    }
}

pub fn exec_sym_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {
        println!("\n{}", *SYM_STRING);

        let cmd = get_command(authkey)?;
        let res = match cmd {
            SymCommand::List => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::List);
                list(session)
            },
            SymCommand::GetKeyProperties => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::GetKeyProperties);
                print_key_properties(session)
            },
            SymCommand::Generate => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::Generate);
                generate(session, authkey)
            },
            SymCommand::Import => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::Import);
                import(session, authkey)
            },
            SymCommand::Delete => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::Delete);
                delete(session)
            },
            SymCommand::Encrypt => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::Encrypt);
                operate(session, authkey, EncryptionMode::Encrypt)
            },
            SymCommand::Decrypt => {
                println!("\n{} > {}\n", *SYM_STRING, SymCommand::Decrypt);
                operate(session, authkey, EncryptionMode::Decrypt)
            },
            SymCommand::ReturnToMainMenu => return Ok(()),
            SymCommand::Exit => std::process::exit(0),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn get_command(authkey: &ObjectDescriptor) -> Result<SymCommand, MgmError> {
    let capabilities= &authkey.capabilities;

    let mut commands = cliclack::select("").initial_value(SymCommand::List);
    commands = commands.item(SymCommand::List, SymCommand::List, "");
    commands = commands.item(SymCommand::GetKeyProperties, SymCommand::GetKeyProperties, "");
    if capabilities.contains(&ObjectCapability::GenerateSymmetricKey) {
        commands = commands.item(SymCommand::Generate, SymCommand::Generate, "");
    }
    if capabilities.contains(&ObjectCapability::PutSymmetricKey) {
        commands = commands.item(SymCommand::Import, SymCommand::Import, "");
    }
    if capabilities.contains(&ObjectCapability::DeleteSymmetricKey) {
        commands = commands.item(SymCommand::Delete, SymCommand::Delete, "");
    }
    if capabilities.contains(&ObjectCapability::EncryptEcb) ||
        capabilities.contains(&ObjectCapability::EncryptCbc) {
        commands = commands.item(SymCommand::Encrypt, SymCommand::Encrypt, "");
    }
    if capabilities.contains(&ObjectCapability::DecryptEcb) ||
        capabilities.contains(&ObjectCapability::DecryptCbc) {
        commands = commands.item(SymCommand::Decrypt, SymCommand::Decrypt, "");
    }
    commands = commands.item(SymCommand::ReturnToMainMenu, SymCommand::ReturnToMainMenu, "");
    commands = commands.item(SymCommand::Exit, SymCommand::Exit, "");
    Ok(commands.interact()?)
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = get_sym_keys(session)?;
    list_objects(session, &keys)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(session, get_sym_keys(session)?)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let algorithm = cliclack::select("Choose key algorithm:")
        .item(ObjectAlgorithm::Aes128, "AES128", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes128))
        .item(ObjectAlgorithm::Aes192, "AES192", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes192))
        .item(ObjectAlgorithm::Aes256, "AES256", format!("yubihsm-shell name: {}", ObjectAlgorithm::Aes256))
        .interact()?;

    let mut new_key = get_new_object_basics(
        authkey, ObjectType::SymmetricKey, &AES_KEY_CAPABILITIES, &[])?;
    new_key.algorithm = algorithm;

    cliclack::note("Generating AES key with:", get_new_object_note(&new_key))?;

    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating AES key...");
        new_key.id = crate::backend::sym_utils::generate(session, &new_key)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated AES key with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key = read_aes_key_hex("Enter AES key in HEX format:")?;

    let mut new_key = ObjectDescriptor::new();
    new_key.algorithm = get_algorithm_from_keylen(key.len())?;
    fill_new_object_properties(&mut new_key, authkey, &AES_KEY_CAPABILITIES, &[])?;

    cliclack::note("Import AES key with:", get_new_object_note(&new_key))?;

    if cliclack::confirm("Import key?").interact()? {
        new_key.id = crate::backend::sym_utils::import(session, &new_key, &key)?;
        cliclack::log::success(
            format!("Imported AES key with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(session, &get_sym_keys(session)?)?;
    delete_objects(session, &objects)
}

fn operate(session: &Session, authkey: &ObjectDescriptor, enc_mode: EncryptionMode) -> Result<(), MgmError> {

    let mut aes_mode = cliclack::select("Select AES encryption mode");
    if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptEcb)) ||
        (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptEcb)) {
        aes_mode = aes_mode.item(AesMode::Ecb, "ECB", "");
    }
    if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptCbc)) ||
        (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptCbc)) {
        aes_mode = aes_mode.item(AesMode::Cbc, "CBC", "")
    }
    let aes_mode = aes_mode.interact()?;

    let op_capability = match aes_mode {
        AesMode::Ecb => if enc_mode == EncryptionMode::Encrypt {ObjectCapability::EncryptEcb} else {ObjectCapability::DecryptEcb},
        AesMode::Cbc => if enc_mode == EncryptionMode::Encrypt {ObjectCapability::EncryptCbc} else {ObjectCapability::DecryptCbc},
    };
    let key = get_operation_key(
        session, authkey,
        [op_capability].to_vec().as_ref(),
        ObjectType::SymmetricKey,
        &[])?;

    let in_data = read_input_bytes(
        "Enter data in hex or path to binary file (data must be a multiple of 16 bytes long):", true)?;
    if in_data.len() % 16 != 0 {
        return Err(MgmError::InvalidInput("Input data not a multiple of 16 bytes".to_string()))
    }

    let iv = if aes_mode == AesMode::Cbc {
        get_iv()?
    } else {
        vec![]
    };

    let out_data = crate::backend::sym_utils::operate(session, &key, aes_mode, enc_mode, iv.as_slice(), &in_data)?;

    cliclack::log::success(hex::encode(&out_data))?;

    if cliclack::confirm("Write to binary file?").interact()? {
        let filename = if enc_mode == EncryptionMode::Encrypt {"data.enc"} else {"data.dec"};
        if let Err(err) = write_bytes_to_file(out_data, "", filename) {
            cliclack::log::error(format!("Failed to write binary data to file. {}", err))?;
        }
    }

    Ok(())
}

fn get_iv() -> Result<Vec<u8>, MgmError> {
    let iv: String = cliclack::input("Enter 16 bytes IV in HEX format:")
        .default_input("00000000000000000000000000000000")
        .validate(|input: &String| {
            if hex::decode(input).is_err() {
                Err("Input must be in hex format")
            } else if input.len() != 32 {
                Err("IV must be 16 bytes long")
            } else {
                Ok(())
            }
        }).interact()?;
    Ok(hex::decode(iv)?)
}
