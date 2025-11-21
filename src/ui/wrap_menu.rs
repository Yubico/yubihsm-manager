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
use crate::traits::ui_traits::YubihsmUi;
use crate::cli::cmdline::Cmdline;
use crate::ui::helper_operations::{delete_objects, display_menu_headers, generate_object, list_objects};
use crate::ui::helper_operations::display_object_properties;
use crate::ui::device_menu::DeviceMenu;
use crate::ui::asym_menu::AsymmetricMenu;
use crate::traits::backend_traits::YubihsmOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::{MgmCommandType, NewObjectSpec, SelectionItem};
use crate::hsm_operations::validators::{aes_key_validator, pem_private_rsa_file_validator, pem_public_rsa_file_validator};
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::sym::SymmetricOperations;
use crate::hsm_operations::wrap::{WrapKeyType, WrapOperations, WrapOpSpec, WrapType};
use crate::hsm_operations::common::get_delegated_capabilities;
use crate::ui::helper_io::{get_pem_from_file, write_bytes_to_file};

static WRAP_HEADER: &str = "Wrap keys";

pub struct WrapMenu<T: YubihsmUi + Clone> {
    ui: T,
}

impl<T: YubihsmUi + Clone> WrapMenu<T> {

    pub fn new(interface: T) -> Self {
        WrapMenu { ui: interface  }
    }
    
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, WRAP_HEADER],
                                 "Wrap key operations allow you to manage and use wrap keys keys stored on the YubiHSM")?;

            let cmd = self.ui.select_command(&WrapOperations.get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, WRAP_HEADER, cmd.label], cmd.description)?;

            let result = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &WrapOperations, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&self.ui, &WrapOperations, session),
                MgmCommandType::Generate => generate_object(&self.ui, &WrapOperations, session, authkey, ObjectType::WrapKey),
                MgmCommandType::Import => self.import(session, authkey),
                MgmCommandType::Delete => delete_objects(&self.ui, &WrapOperations, session, &WrapOperations.get_all_objects(session)?),
                MgmCommandType::GetPublicKey => AsymmetricMenu::new(Cmdline).get_public_key(session, ObjectType::WrapKey),
                MgmCommandType::ExportWrapped => self.export_wrapped(session, authkey),
                MgmCommandType::ImportWrapped => self.import_wrapped(session, authkey),
                MgmCommandType::GetRandom => DeviceMenu::new(self.ui.clone()).get_random(session),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(err) = result {
                self.ui.display_error_message(err.to_string().as_str())?;
            }
        }
    }

    pub fn import(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        if self.ui.get_confirmation("Re-create from shares?")? {
            self.import_from_shares(session)
        } else {
            self.import_full_key(session, authkey)
        }
    }

    fn import_full_key(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let mut new_key = NewObjectSpec::empty();


        let mut input = self.ui.get_string_input(
            "Enter wrap key in HEX format or path to PEM file containing RSA key:", true)?;
        loop {
            if aes_key_validator(&input).is_ok() || pem_private_rsa_file_validator(&input).is_ok() || pem_public_rsa_file_validator(&input).is_ok() {
                break;
            }
            self.ui.display_error_message("Input is neither valid AES key in HEX format nor valid path to a file containing RSA key in PEM format")?;
            input = self.ui.get_string_input(
                "Try again or press ESC to return to menu:", true)?;
        }

        if aes_key_validator(&input).is_ok() {
            self.ui.display_info_message("Detected HEX string. Parsing as AES wrap key...")?;
            new_key.object_type = ObjectType::WrapKey;
            new_key.data.push(hex::decode(input)?);
            new_key.algorithm = WrapOperations::get_algorithm_from_keylen(new_key.data[0].len())?;
        } else if pem_private_rsa_file_validator(&input).is_ok() || pem_public_rsa_file_validator(&input).is_ok() {
            self.ui.display_info_message("Detected PEM file with private RSA key. Parsing as RSA key...")?;
            let pem = get_pem_from_file(&input)?[0].clone();
            let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
            new_key.data.push(_bytes);
            new_key.algorithm = _algo;
            match _type {
                ObjectType::AsymmetricKey => new_key.object_type = ObjectType::WrapKey,
                ObjectType::PublicKey => new_key.object_type = ObjectType::PublicWrapKey,
                _ => unreachable!()
            }
        } else {
            unreachable!();
        }
        let key_type = WrapOperations::get_wrapkey_type(new_key.object_type, new_key.algorithm)?;

        new_key.id = self.ui.get_new_object_id(0)?;
        new_key.label = self.ui.get_object_label("")?;
        new_key.domains = self.ui.select_object_domains(&authkey.domains)?;
        new_key.capabilities = self.ui.select_object_capabilities(
            &WrapOperations.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
            &[],
            Some("Select object capabilities"))?;
        new_key.delegated_capabilities = self.ui.select_object_capabilities(
            &get_delegated_capabilities(authkey),
            &get_delegated_capabilities(authkey),
            Some("Select delegated capabilities"))?;

        if !self.ui.get_note_confirmation(
            "Import wrap key with:",
            &new_key.to_string())? {
            self.ui.display_info_message("Object is not imported")?;
            return Ok(());
        }

        let spinner = self.ui.start_spinner(Some("Generating key..."));
        new_key.id = WrapOperations.import(session, &new_key)?;
        self.ui.stop_spinner(spinner, None);
        self.ui.display_success_message(format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object_type, new_key.id).as_str())?;


        if key_type != WrapKeyType::Aes {
            return Ok(());
        }

        self.ui.display_info_message("Split wrap key? Note that the wrap key is already imported into the YubiHSM2. Key split is done outside the device")?;
        if self.ui.get_confirmation("Split wrap key?")? {
            let n_shares = self.ui.get_split_aes_n_shares("Enter the number of shares to create:")?;
            let n_threshold = self.ui.get_split_aes_m_threshold("Enter the number of shares necessary to re-create the key:", n_shares)?;
            let split_key = WrapOperations::split_wrap_key(&new_key, n_threshold, n_shares)?;
            self.display_wrapkey_shares(split_key.shares_data)?;
        }

        Ok(())
    }

    fn import_from_shares(&self, session: &Session) -> Result<(), MgmError> {
        let shares = self.recover_wrapkey_shares()?;
        let mut new_key = WrapOperations::get_wrapkey_from_shares(shares)?;
        new_key.label = self.ui.get_object_label("")?;

        if !self.ui.get_note_confirmation("Import wrap key with:", new_key.to_string().as_str())? {
            self.ui.display_info_message("Key is not imported")?;
            return Ok(());
        }

        let spinner = self.ui.start_spinner(Some("Importing key..."));
        new_key.id = WrapOperations.import(session, &new_key)?;
        self.ui.stop_spinner(spinner, None);

        self.ui.display_success_message(format!("Imported wrap key with ID 0x{:04x} on the device", new_key.id).as_str())?;
        Ok(())
    }

    fn export_wrapped(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let wrapkeys = WrapOperations::get_wrapping_keys(session, authkey)?;
        let wrapkey = self.ui.select_one_object(
            &wrapkeys,
            Some("Select the wrapping key to use for exporting objects:"))?;
        let wrapkey_type = WrapOperations::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

        let wrap_type = match wrapkey_type {
            WrapKeyType::Aes => WrapType::Object,
            WrapKeyType::RsaPublic => {
                self.ui.select_one_item(
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

        let exportable_objects = WrapOperations::get_exportable_objects(session, &wrapkey, wrap_type)?;
        let export_objects = self.ui.select_multiple_objects(
            &exportable_objects,
            false,
            Some("Select objects to export"))?;
        if exportable_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
            wrap_op.include_ed_seed = self.ui.get_confirmation("Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)")?;
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

        let dir = self.ui.get_path_input(
            "Enter path to backup directory:",
            false,
            Some("."),
            Some("Default is current directory"))?;

        let wrapped_objects = WrapOperations::export_wrapped(session, &wrap_op, &export_objects)?;

        for object in &wrapped_objects {
            if object.error.is_some() {
                self.ui.display_warning(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()).as_str())?;
                continue;
            }
            let filename = format!("0x{:04x}-{}.yhw", object.object_id, object.object_type);
            write_bytes_to_file(&self.ui, base64::encode_block(&object.wrapped_data).as_bytes(), filename.as_str(), Some(&dir))?;
        }

        Ok(())
    }

    fn import_wrapped(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let filepath = self.ui.get_path_input(
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

        let wrapkeys = WrapOperations::get_unwrapping_keys(session, authkey)?;
        let wrapkey = self.ui.select_one_object(
            &wrapkeys,
            Some("Select the unwrapping key to use for importing objects:"))?;
        let wrapkey_type = WrapOperations::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

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
                Some("Select OAEP algorithm to use for wrapping"))?);
        }

        let res = WrapOperations::import_wrapped(session, &wrap_op, wrapped.clone(), None);
        let handle = match res {
            Ok(h) => h,
            Err(e) => {
                if wrapkey_type == WrapKeyType::Rsa {
                    self.ui.display_info_message("Failed to unwrap as object, trying as key data...")?;

                    let algo = self.ui.select_algorithm(
                        &WrapOperations::get_unwrapped_key_algorithms(),
                        None,
                        Some("Select wrapped key algorithm"))?;
                    let caps = if SymmetricOperations::is_aes_algorithm(&algo) {
                        SymmetricOperations.get_applicable_capabilities(&wrapkey, None, None)?
                    } else {
                        AsymmetricOperations.get_applicable_capabilities(&wrapkey, None, Some(algo))?
                    };

                    let mut new_key = NewObjectSpec::empty();
                    new_key.algorithm = algo;
                    new_key.id = self.ui.get_new_object_id(0)?;
                    new_key.label = self.ui.get_object_label("")?;
                    new_key.domains = self.ui.select_object_domains(&authkey.domains)?;
                    new_key.capabilities = self.ui.select_object_capabilities(
                        &caps,
                        &[],
                        Some("Select object capabilities"))?;

                    WrapOperations::import_wrapped(session, &wrap_op, wrapped, Some(new_key))?
                } else {
                    return Err(e)
                }
            }
        };

        self.ui.display_success_message(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id).as_str())?;

        Ok(())
    }

    pub fn display_wrapkey_shares(&self, shares: Vec<String>) -> Result<(), MgmError> {
        self.ui.display_warning(
            "*************************************************************\n\
        * WARNING! The following shares will NOT be stored anywhere *\n\
        * Save them and store them safely if you wish to re-use   *\n\
        * the wrap key for this device in the future                *\n\
        *************************************************************")?;

        self.ui.get_string_input("Press Enter to start saving key shares", false)?;

        for share in shares {
            loop {
                self.ui.clear_screen()?;
                self.ui.display_note("", &share)?;
                if self.ui.get_confirmation("Have you saved the key share?")? {
                    break;
                }
            }
            self.ui.clear_screen()?;
            self.ui.get_string_input("Press any key to display next key share or to return to menu", false)?;
        }

        self.ui.clear_screen()?;
        Ok(())
    }

    fn recover_wrapkey_shares(&self) -> Result<Vec<String>, MgmError> {
        self.ui.display_warning("Note that the wrap key will be recreated outside the YubiHSM before importing it in its whole into the device")?;
        self.ui.get_string_input("Press any key to recreate wrap key from shares", false)?;

        let n_shares = self.ui.get_split_aes_n_shares(
            "Enter the number of shares to re-create the AES wrap key:")?;
        let mut shares_vec = Vec::new();

        self.ui.clear_screen()?;
        shares_vec.push(self.ui.get_split_aes_share("Enter share number 1:", None)?);

        if n_shares > 1 {
            for i in 2..=n_shares {
                self.ui.clear_screen()?;
                shares_vec.push(self.ui.get_split_aes_share(format!("Enter share number {}:", i).as_str(), Some(shares_vec[0].len() as u8))?);
            }
        }
        self.ui.clear_screen()?;

        self.ui.display_info_message(format!("{} shares have been registered", n_shares).as_str())?;

        Ok(shares_vec)
    }
}