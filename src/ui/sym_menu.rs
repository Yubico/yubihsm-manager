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
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::helper_operations::{generate_object, import_object, list_objects};
use crate::ui::helper_operations::{delete_objects, display_menu_headers, display_object_properties};
use crate::ui::device_menu::DeviceMenu;
use crate::traits::backend_traits::YubihsmOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::{MgmCommandType, SelectionItem};
use crate::hsm_operations::sym::{AesMode, AesOperationSpec, EncryptionMode, SymmetricOperations};
use crate::ui::helper_io::{get_hex_or_bytes_from_file, write_bytes_to_file};

static SYM_HEADER: &str = "Symmetric keys";

pub struct SymmetricMenu<T: YubihsmUi + Clone> {
    ui: T,
}

impl<T: YubihsmUi + Clone> SymmetricMenu<T> {

    pub fn new(interface: T) -> Self {
        SymmetricMenu { ui: interface  }
    }
    
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, SYM_HEADER],
                                 "Symmetric key operations allow you to manage and use symmetric keys stored on the YubiHSM")?;

            let cmd = self.ui.select_command(&SymmetricOperations.get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, SYM_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &SymmetricOperations, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&self.ui, &SymmetricOperations, session),
                MgmCommandType::Generate => generate_object(&self.ui, &SymmetricOperations, session, authkey, ObjectType::SymmetricKey),
                MgmCommandType::Import => self.import(session, authkey),
                MgmCommandType::Delete => delete_objects(&self.ui, &SymmetricOperations, session, &SymmetricOperations.get_all_objects(session)?),
                MgmCommandType::Encrypt => self.operate(session, authkey, EncryptionMode::Encrypt),
                MgmCommandType::Decrypt => self.operate(session, authkey, EncryptionMode::Decrypt),
                MgmCommandType::GetRandom => DeviceMenu::new(self.ui.clone()).get_random(session),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                self.ui.display_error_message(e.to_string().as_str())?
            }
        }
    }

    pub fn import(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let mut key_data = vec![];
        key_data.push(self.ui.get_aes_key_hex("Enter AES key in HEX format:")?);
        let key_algo = SymmetricOperations::get_symkey_algorithm_from_keylen(key_data[0].len())?;

        import_object(&self.ui, &SymmetricOperations, session, authkey, ObjectType::SymmetricKey, key_algo, key_data)
    }

    fn operate(&self, session: &Session, authkey: &ObjectDescriptor, enc_mode: EncryptionMode) -> Result<(), MgmError> {
        let mut aes_mode = vec![];
        if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptEcb)) || (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptEcb)) {
            aes_mode.push(SelectionItem::new(AesMode::Ecb, "ECB".to_string(), "".to_string()));
        }
        if (enc_mode == EncryptionMode::Encrypt && authkey.capabilities.contains(&ObjectCapability::EncryptCbc)) || (enc_mode == EncryptionMode::Decrypt && authkey.capabilities.contains(&ObjectCapability::DecryptCbc)) {
            aes_mode.push(SelectionItem::new(AesMode::Cbc, "CBC".to_string(), "".to_string()));
        }
        let aes_mode = self.ui.select_one_item(
            &aes_mode,
            None,
            Some("Select AES encryption mode:"))?;

        let key = self.ui.select_one_object(&SymmetricOperations::get_operation_keys(session, authkey, enc_mode, aes_mode)?, Some("Select AES key for operation:"))?;


        let in_data = self.ui.get_string_input(
            "Enter data in hex or absolut path to binary file (data must be a multiple of 16 bytes long):", true)?;
        let in_data = get_hex_or_bytes_from_file(&self.ui, in_data)?;
        if in_data.len() % 16 != 0 {
            return Err(MgmError::InvalidInput("Input data must be a multiple of 16 bytes".to_string()))
        }

        let iv = if aes_mode == AesMode::Cbc {
            self.ui.get_aes_iv_hex("Enter 16 bytes IV in HEX format:", false, Some("00000000000000000000000000000000"))?
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
        let out_data = SymmetricOperations::operate(session, op_spec)?;

        self.ui.display_success_message(hex::encode(&out_data).as_str())?;

        if self.ui.get_confirmation("Write to binary file?")? {
            let filename = if enc_mode == EncryptionMode::Encrypt { "data.enc" } else { "data.dec" };
            if let Err(err) = write_bytes_to_file(&self.ui, &out_data, filename, None) {
                self.ui.display_error_message(format!("Failed to write binary data to file. {}", err).as_str())?;
            }
        }

        Ok(())
    }
}