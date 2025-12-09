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
use crate::ui::helper_operations::{generate_object, import_object, list_objects};
use crate::ui::helper_operations::{delete_objects, display_menu_headers, display_object_properties};
use crate::traits::operation_traits::YubihsmOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::MgmCommandType;
use crate::hsm_operations::asym::{AsymmetricOperations, JavaOps};
use crate::ui::helper_io::get_pem_from_file;


static JAVA_HEADER: &str = "SunPKCS11 keys";

pub struct JavaMenu<T: YubihsmUi> {
    ui: T,
}

impl<T: YubihsmUi> JavaMenu<T> {

    pub fn new(interface: T) -> Self {
        JavaMenu { ui: interface  }
    }

    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, JAVA_HEADER],
                                 "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate are store in the device with the same ObjectID")?;

            let cmd = self.ui.select_command(&JavaOps.get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, JAVA_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &JavaOps, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&self.ui, &JavaOps, session),
                MgmCommandType::Generate => generate_object(&self.ui, &JavaOps, session, authkey, ObjectType::AsymmetricKey),
                MgmCommandType::Import => self.import(session, authkey),
                MgmCommandType::Delete => delete_objects(&self.ui, &JavaOps, session, &JavaOps.get_all_objects(session)?),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(e) = res {
                self.ui.display_error_message(e.to_string().as_str())
            }
        }
    }

    fn import(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        let filepath = self.ui.get_sunpkcs11_import_filepath(
            "Enter absolute path to PEM file containing private key and X509Certificate (Only the first object of its type will be imported):",
            None)?;
        let pems = get_pem_from_file(&filepath)?;
        if pems.len() > 2 {
            self.ui.display_warning("Warning!! More than two PEM objects found in file. Only the first private key and first X509Certificate will be imported");
        }

        let (algo, key) = Self::get_first_object_from_pem(pems.clone(), ObjectType::AsymmetricKey)?;
        self.ui.display_info_message("Private key loaded from PEM file");
        let (_, cert) = Self::get_first_object_from_pem(pems.clone(), ObjectType::Opaque)?;
        self.ui.display_info_message("X509Certificate loaded from PEM file");

        import_object(&self.ui, &JavaOps, session, authkey, ObjectType::AsymmetricKey, algo, [key, cert].to_vec())
    }

    fn get_first_object_from_pem(pems: Vec<Pem>, object_type: ObjectType) -> Result<(ObjectAlgorithm, Vec<u8>), MgmError> {
        for pem in pems {
            let (_type, _algo, _value) = AsymmetricOperations::parse_asym_pem(pem)?;
            if _type == object_type {
                return Ok((_algo, _value));
            }
        }
        Err(MgmError::Error(format!("No object of type {} found in PEM file", object_type)))
    }
}