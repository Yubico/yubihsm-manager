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
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::helper_operations::display_menu_headers;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::device::DeviceOperations;
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::types::MgmCommandType;
use crate::hsm_operations::wrap::{WrapKeyType, WrapOperations, WrapOpSpec, WrapType};
use crate::ui::helper_io::{write_bytes_to_file, get_path};

static DEVICE_HEADER: &str = "YubiHSM Device Operations";

pub struct DeviceMenu<T: YubihsmUi> {
    ui: T,
}

impl<T: YubihsmUi> DeviceMenu<T> {

    pub fn new(interface: T) -> Self {
        DeviceMenu { ui: interface  }
    }
    
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, DEVICE_HEADER],
                                 "Device operations allow you to do device wide operations such as backup, restore, reset, and getting random bytes.")?;

            let cmd = self.ui.select_command(&DeviceOperations::get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::GetRandom => self.get_random(session),
                MgmCommandType::BackupDevice => self.backup(session, authkey),
                MgmCommandType::RestoreDevice => self.restore(session, authkey),
                MgmCommandType::Reset => self.reset(session),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                self.ui.display_error_message(e.to_string().as_str())
            }
        }
    }

    pub fn get_random(&self, session: &Session) -> Result<(), MgmError> {
        let n: usize = self.ui.get_integer_input(
            "Enter number of bytes",
            false,
            Some(256),
            Some("Can be maximum of 2028 bytes for newer YubiHSMs or 2021 for older ones. Default is 256"),
            1,
            2028)?;
        let bytes = DeviceOperations::get_random(session, n)?;
        self.ui.display_success_message(hex::encode(bytes).to_string().as_str());
        Ok(())
    }


    fn backup(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let wrapkeys = WrapOperations::get_wrapping_keys(session, authkey)?;
        let wrapkey = self.ui.select_one_object(
            &wrapkeys,
            Some("Select the wrapping key to use for exporting objects:"))?;
        let wrapkey_type = WrapOperations::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

        let mut wrap_op = WrapOpSpec {
            wrapkey_id: wrapkey.id,
            wrapkey_type,
            wrap_type: WrapType::Object,
            include_ed_seed: false,
            aes_algorithm: None,
            oaep_algorithm: None,
        };

        let export_objects = WrapOperations::get_exportable_objects(session, &wrapkey, WrapType::Object)?;
        if export_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
            wrap_op.include_ed_seed = self.ui.get_confirmation("Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)")?
        };

        if wrapkey_type == WrapKeyType::RsaPublic {
            wrap_op.aes_algorithm = Some(self.ui.select_algorithm(
                &SymmetricOperations.get_generation_algorithms(),
                Some(ObjectAlgorithm::Aes256),
                Some("Select AES algorithm to use for wrapping"))?);
            wrap_op.oaep_algorithm = Some(self.ui.select_algorithm(
                &MgmAlgorithm::RSA_OAEP_ALGORITHMS,
                Some(ObjectAlgorithm::RsaOaepSha256),
                Some("Select OAEP algorithm to use for wrapping"))?);
        }

        let dir = get_path(&self.ui, "Enter path to backup directory:", true, "")?;

        let wrapped_objects = WrapOperations::export_wrapped(session, &wrap_op, &export_objects)?;

        for object in &wrapped_objects {
            if object.error.is_some() {
                self.ui.display_error_message(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()).as_str());
                continue;
            }
            let filename = format!("{}/0x{:04x}-{}.yhw", dir, object.object_id, object.object_type);
            write_bytes_to_file(&self.ui, openssl::base64::encode_block(&object.wrapped_data).as_bytes(), filename.as_str())?;
        }

        Ok(())
    }

    fn restore(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let wrapkeys = WrapOperations::get_unwrapping_keys(session, authkey)?;
        let wrapkey = self.ui.select_one_object(
            &wrapkeys,
            Some("Select the unwrapping key to use for importing objects:"))?;
        let wrapkey_type = WrapOperations::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

        let dir = self.ui.get_path_input(
            "Enter path to backup directory:",
            false,
            Some("."),
            Some("Default is current directory"))?;

        let files: Vec<_> = match scan_dir::ScanDir::files().read(dir.clone(), |iter| {
            iter.filter(|(_, name)| name.ends_with(".yhw")).map(|(entry, _)| entry.path()).collect()
        }) {
            Ok(f) => f,
            Err(err) => {
                self.ui.display_error_message(err.to_string().as_str());
                return Err(MgmError::Error("Failed to read files".to_string()))
            }
        };

        if files.is_empty() {
            self.ui.display_info_message(format!("No backup files were found in {}", dir).as_str());
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
            wrap_op.oaep_algorithm = Some(self.ui.select_algorithm(
                &MgmAlgorithm::RSA_OAEP_ALGORITHMS,
                Some(ObjectAlgorithm::RsaOaepSha256),
                Some("Select OAEP algorithm to use for unwrapping", ))?);
        }

        for f in files {
            self.ui.display_info_message(format!("reading {}", &f.display()).as_str());
            let mut file = File::open(&f)?;

            let mut wrap = String::new();
            file.read_to_string(&mut wrap)?;

            let res = WrapOperations::import_wrapped(session, &wrap_op, wrap, None);
            match res {
                Ok(handle) => {
                    self.ui.display_success_message(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id).as_str());
                },
                Err(e) => {
                    self.ui.display_error_message(format!("Failed to import wrapped object from file {}: {}. Skipping...", f.display(), e).as_str());
                }
            }
        }
        Ok(())
    }

    pub fn reset(&self, session: &Session) -> Result<(), MgmError> {
        if self.ui.get_warning_confirmation("All data will be deleted from the device and cannot be recovered.")? {
            DeviceOperations::reset_device(session)?;
            self.ui.display_success_message("Device has been reset to factory defaults.");
        }
        Ok(())
    }
}