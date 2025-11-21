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

use pem::Pem;

use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::utils::{generate_object, import_object, list_objects};
use crate::ui::utils::{display_menu_headers, display_object_properties, get_pem_from_file, delete_objects};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::traits::backend_traits::YubihsmOperations;
use crate::backend::error::MgmError;
use crate::backend::types::{MgmCommandType};
use crate::backend::asym::{AsymOps, JavaOps};


static JAVA_HEADER: &str = "SunPKCS11 keys";

pub struct JavaMenu;

impl JavaMenu {
    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER],
                                 "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate are store in the device with the same ObjectID")?;

            let cmd = YubihsmUi::select_command(&Cmdline, &JavaOps.get_authorized_commands(authkey))?;
            display_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&JavaOps, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&JavaOps, session),
                MgmCommandType::Generate => generate_object(&JavaOps, session, authkey, ObjectType::AsymmetricKey),
                MgmCommandType::Import => Self::import(session, authkey),
                MgmCommandType::Delete => delete_objects(&JavaOps, session, &JavaOps.get_all_objects(session)?),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
            }
        }
    }

    fn import(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let filepath = YubihsmUi::get_pem_filepath(
            &Cmdline,
            "Enter absolute path to PEM file containing private key and/or X509Certificate (Only the first object of its type will be imported):",
            true,
            None)?;
        let mut pems = get_pem_from_file(&filepath)?;

        let object_algorithm;
        let mut key_data: Vec<Vec<u8>> = Vec::new();
        loop {
            if let Ok((_algo, _value)) = Self::get_first_object_from_pem(pems.clone(), ObjectType::AsymmetricKey) {
                object_algorithm = _algo;
                key_data.push(_value);
                break;
            }
            YubihsmUi::display_error_message(&Cmdline, "No private key found in PEM file. Please try again or press ESC to go back to menu")?;
            pems = get_pem_from_file(&YubihsmUi::get_pem_filepath(
                &Cmdline,
                "Enter absolute path to PEM file containing a private key:",
                true,
                None)?)?;
        }
        YubihsmUi::display_info_message(&Cmdline, "Private key loaded from PEM file")?;

        loop {
            if let Ok((_, _value)) = Self::get_first_object_from_pem(pems.clone(), ObjectType::Opaque) {
                key_data.push(_value);
                break;
            }
            YubihsmUi::display_error_message(&Cmdline, "No X509Certificate found in PEM file. Please try again or press ESC to go back to menu")?;
            pems = get_pem_from_file(&YubihsmUi::get_pem_filepath(
                &Cmdline,
                "Enter absolute path to PEM file containing an X509Certificate:",
                true,
                None)?)?;
        }
        YubihsmUi::display_info_message(&Cmdline, "X509Certificate loaded from PEM file")?;

        import_object(&JavaOps, session, authkey, ObjectType::AsymmetricKey, object_algorithm, key_data)
    }

    fn get_first_object_from_pem(pems: Vec<Pem>, object_type: ObjectType) -> Result<(ObjectAlgorithm, Vec<u8>), MgmError> {
        for pem in pems {
            let (_type, _algo, _value) = AsymOps::parse_asym_pem(pem)?;
            if _type == object_type {
                return Ok((_algo, _value));
            }
        }
        Err(MgmError::Error(format!("No object of type {} found in PEM file", object_type)))
    }
}