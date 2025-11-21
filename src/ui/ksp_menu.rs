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

use openssl::base64;
use yubihsmrs::object::{ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::wrap_menu::WrapMenu;
use crate::ui::utils::{display_menu_headers, write_bytes_to_file};
use crate::backend::error::MgmError;
use crate::backend::ksp::KspOps;
use crate::backend::wrap::{WrapKeyType, WrapOps, WrapType, WrapOpSpec};

static KSP_HEADER: &str = "KSP Setup";

pub struct Ksp<T: YubihsmUi + Clone> {
    ui: T,
}

impl<T: YubihsmUi + Clone> Ksp<T> {

    pub fn new(interface: T) -> Self {
        Ksp { ui: interface  }
    }

    pub fn guided_setup(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

        let intro_text = "Follow this guided setup to prepare the YubiHSM to be used with Windows KSP/CNG provider.\n\
    You will be prompted to enter values for the wrap key and authentication keys.\n\
    Please ensure you have the necessary permissions and that you record the wrap key shares securely.";

        display_menu_headers(&self.ui, &[crate::MAIN_HEADER, KSP_HEADER], intro_text)?;


        self.ui.display_info_message("Beginning the setup process.")?;

        KspOps::check_privileges(authkey)?;
        self.ui.display_info_message("User has sufficient privileges to perform KSP setup.")?;

        let rsa_decrypt = self.ui.get_confirmation("Add RSA decryption capabilities?")?;

        self.ui.display_info_message("Importing KSP wrap key...")?;
        let id = self.ui.get_new_object_id(0)?;
        let domains = self.ui.select_object_domains(&authkey.domains)?;
        let shares = self.ui.get_split_aes_n_shares("Enter the number of shares to create:")?;
        let threshold = self.ui.get_split_aes_m_threshold("Enter the number of shares necessary to re-create the key:", shares)?;
        let (wrapkey_id, wrapkey_shares) = KspOps::import_ksp_wrapkey(
            session, id, &domains, rsa_decrypt, shares, threshold)?;
        self.ui.display_success_message(format!("Successfully imported wrap key with ID  0x{:04x}", wrapkey_id).as_str())?;
        self.ui.get_string_input("Press any key to start recording wrap key shares", true)?;

        WrapMenu::new(self.ui.clone()).display_wrapkey_shares(wrapkey_shares.shares_data)?;
        self.ui.display_info_message("All key shares have been recorded and cannot be displayed again\n")?;

        self.ui.display_info_message("Importing application authentication key...")?;
        let appkey_desc = KspOps::import_app_authkey(
            session,
            self.ui.get_new_object_id(0)?,
            &domains,
            rsa_decrypt,
            self.ui.get_password("Enter application authentication key password:", true)?,
        )?;
        self.ui.display_success_message(format!("Successfully imported application authentication key with ID  0x{:04x}", appkey_desc.id).as_str())?;

        let auditkey = if self.ui.get_confirmation("Create an audit key? ")? {
            self.ui.display_info_message("Importing audit key...")?;
            let key_desc = KspOps::import_audit_authkey(
                session,
                self.ui.get_new_object_id(0)?,
                &domains,
                self.ui.get_password("Enter audit key password:", true)?,
            )?;
            self.ui.display_success_message(format!("Successfully imported audit key with ID  0x{:04x}", key_desc.id).as_str())?;
            Some(key_desc)
        } else {
            None
        };

        if self.ui.get_confirmation("Export keys? ")? {
            self.export_keys(session, wrapkey_id, appkey_desc, auditkey)?;
        }

        self.ui.display_success_message("KSP setup completed successfully!")?;

        if self.ui.get_confirmation("Delete the current authentication key (strongly recommended)?")? {
            session.delete_object(authkey.id, ObjectType::AuthenticationKey)?;
        }

        Ok(())
    }

    fn export_keys(&self, session: &Session, wrapkey_id: u16, appkey: ObjectDescriptor, auditkey: Option<ObjectDescriptor>) -> Result<(), MgmError> {
        let dir = self.ui.get_path_input(
            "Enter export destination directory:",
            false,
            Some("."),
            Some("Default is current directory"))?;

        let mut export_objects = vec![appkey];
        if let Some(key) = auditkey {
            export_objects.push(key);
        }

        let wrap_op_spec = WrapOpSpec {
            wrapkey_id,
            wrapkey_type: WrapKeyType::Aes,
            wrap_type: WrapType::Object,
            include_ed_seed: false,
            aes_algorithm: None,
            oaep_algorithm: None,
        };

        let wrapped_keys = WrapOps::export_wrapped(session, &wrap_op_spec, &export_objects)?;
        for key in wrapped_keys {
            let filename = format!("0x{:04x}-{}.yhw", key.object_id, key.object_type);
            write_bytes_to_file(&self.ui, base64::encode_block(&key.wrapped_data).as_bytes(), filename.as_str(), Some(&dir))?;
        }

        self.ui.display_info_message(format!("\nAll keys have been exported to {}", dir).as_str())?;

        Ok(())
    }
}