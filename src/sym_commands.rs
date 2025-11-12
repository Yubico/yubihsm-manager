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

use yubihsmrs::object::{ObjectCapability, ObjectDescriptor};
use yubihsmrs::Session;
use crate::utils::select_one_object;
use crate::backend::sym::AesOperationSpec;
use crate::backend::sym::{AesMode, EncryptionMode};
use crate::backend::object_ops::{Deletable, Generatable, Importable, Obtainable};
use crate::backend::sym::SymOps;
use crate::backend::types::{ImportObjectSpec, ObjectSpec};
use crate::utils::{fill_object_spec, list_objects, print_failed_delete, print_object_properties, select_algorithm, select_delete_objects};
use crate::utils::{read_aes_key_hex, read_input_bytes, write_bytes_to_file};
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
    let keys = SymOps.get_all_objects(session)?;
    list_objects(&keys)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(&SymOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(&SymOps.get_all_objects(session)?)?;
    let failed = SymOps.delete_multiple(session, &objects);
    print_failed_delete(&failed)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key_algo = select_algorithm("Select AES key algorithm:", &SymOps::get_object_algorithms(), None)?;

    let mut new_key = ObjectSpec::empty();
    new_key.algorithm = key_algo;
    fill_object_spec(authkey, &mut new_key,  &SymOps::get_object_capabilities(&key_algo), &[])?;

    cliclack::note("Generating AES key with:", new_key.to_string())?;

    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating AES key...");
        new_key.id = SymOps.generate(session, &new_key)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated AES key with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let key = read_aes_key_hex("Enter AES key in HEX format:")?;
    let key_algo = SymOps::get_symkey_algorithm_from_keylen(key.len())?;

    let mut new_key = ImportObjectSpec::empty();
    new_key.data.push(key.clone());
    new_key.object.algorithm = key_algo;
    fill_object_spec(authkey, &mut new_key.object,  &SymOps::get_object_capabilities(&key_algo), &[])?;

    cliclack::note("Import AES key with:", new_key.object.to_string())?;

    if cliclack::confirm("Import key?").interact()? {
        new_key.object.id = SymOps.import(session, &new_key)?;
        cliclack::log::success(
            format!("Imported AES key with ID 0x{:04x} on the device", new_key.object.id))?;
    }
    Ok(())
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

    let key = select_one_object(
        "Select AES key for operation:",
        &SymOps::get_operation_keys(session, authkey, enc_mode, aes_mode)?)?;

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

    let op_spec = AesOperationSpec {
        operation_key: key,
        aes_mode,
        enc_mode,
        iv,
        data: in_data,
    };
    let out_data = SymOps::operate(session, op_spec)?;

    cliclack::log::success(hex::encode(&out_data))?;

    if cliclack::confirm("Write to binary file?").interact()? {
        let filename = if enc_mode == EncryptionMode::Encrypt {"data.enc"} else {"data.dec"};
        if let Err(err) = write_bytes_to_file(&out_data, "", filename) {
            cliclack::log::error(format!("Failed to write binary data to file. {}", err))?;
        }
    }

    Ok(())
}

fn get_iv() -> Result<Vec<u8>, MgmError> {
    let iv: String = cliclack::input("Enter 16 bytes IV in HEX format:")
        .default_input("00000000000000000000000000000000")
        .validate(|input: &String| {
            let hex = hex::decode(input);
            if hex.is_err() {
                Err("Input must be in hex format")
            } else if hex.unwrap().len() != 16 {
                Err("IV must be 16 bytes long")
            } else {
                Ok(())
            }
        }).interact()?;
    Ok(hex::decode(iv)?)
}
