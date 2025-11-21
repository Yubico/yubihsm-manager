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
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::backend::error::MgmError;
use crate::backend::ksp::KspOps;
use crate::backend::wrap::{WrapKeyType, WrapOps, WrapType, WrapOpSpec};

static KSP_HEADER: &str = "KSP Setup";

pub struct Ksp;

impl Ksp {

    pub fn guided_setup(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

        let intro_text = "Follow this guided setup to prepare the YubiHSM to be used with Windows KSP/CNG provider.\n\
    You will be prompted to enter values for the wrap key and authentication keys.\n\
    Please ensure you have the necessary permissions and that you record the wrap key shares securely.";

        display_menu_headers(&[crate::MAIN_HEADER, KSP_HEADER], intro_text)?;


        YubihsmUi::display_info_message(&Cmdline, "Beginning the setup process.")?;

        KspOps::check_privileges(authkey)?;
        YubihsmUi::display_info_message(&Cmdline, "User has sufficient privileges to perform KSP setup.")?;

        let rsa_decrypt = YubihsmUi::get_confirmation(&Cmdline, "Add RSA decryption capabilities?")?;

        YubihsmUi::display_info_message(&Cmdline, "Importing KSP wrap key...")?;
        let id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
        let domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
        let shares = YubihsmUi::get_split_aes_n_shares(&Cmdline, "Enter the number of shares to create:")?;
        let threshold = YubihsmUi::get_split_aes_m_threshold(&Cmdline, "Enter the number of shares necessary to re-create the key:", shares)?;
        let (wrapkey_id, wrapkey_shares) = KspOps::import_ksp_wrapkey(
            session, id, &domains, rsa_decrypt, shares, threshold)?;
        YubihsmUi::display_success_message(&Cmdline, format!("Successfully imported wrap key with ID  0x{:04x}", wrapkey_id).as_str())?;
        YubihsmUi::get_string_input(&Cmdline, "Press any key to start recording wrap key shares", true)?;

        WrapMenu::display_wrapkey_shares(wrapkey_shares.shares_data)?;
        YubihsmUi::display_info_message(&Cmdline, "All key shares have been recorded and cannot be displayed again\n")?;

        YubihsmUi::display_info_message(&Cmdline, "Importing application authentication key...")?;
        let appkey_desc = KspOps::import_app_authkey(
            session,
            YubihsmUi::get_new_object_id(&Cmdline, 0)?,
            &domains,
            rsa_decrypt,
            YubihsmUi::get_password(&Cmdline, "Enter application authentication key password:", true)?,
        )?;
        YubihsmUi::display_success_message(&Cmdline, format!("Successfully imported application authentication key with ID  0x{:04x}", appkey_desc.id).as_str())?;

        let auditkey = if YubihsmUi::get_confirmation(&Cmdline, "Create an audit key? ")? {
            YubihsmUi::display_info_message(&Cmdline, "Importing audit key...")?;
            let key_desc = KspOps::import_audit_authkey(
                session,
                YubihsmUi::get_new_object_id(&Cmdline, 0)?,
                &domains,
                YubihsmUi::get_password(&Cmdline, "Enter audit key password:", true)?,
            )?;
            YubihsmUi::display_success_message(&Cmdline, format!("Successfully imported audit key with ID  0x{:04x}", key_desc.id).as_str())?;
            Some(key_desc)
        } else {
            None
        };

        if YubihsmUi::get_confirmation(&Cmdline, "Export keys? ")? {
            Self::export_keys(session, wrapkey_id, appkey_desc, auditkey)?;
        }

        YubihsmUi::display_success_message(&Cmdline, "KSP setup completed successfully!")?;

        if YubihsmUi::get_confirmation(&Cmdline, "Delete the current authentication key (strongly recommended)?")? {
            session.delete_object(authkey.id, ObjectType::AuthenticationKey)?;
        }

        Ok(())
    }

    fn export_keys(session: &Session, wrapkey_id: u16, appkey: ObjectDescriptor, auditkey: Option<ObjectDescriptor>) -> Result<(), MgmError> {
        let dir = YubihsmUi::get_path_input(
            &Cmdline,
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
            write_bytes_to_file(base64::encode_block(&key.wrapped_data).as_bytes(), filename.as_str(), Some(&dir))?;
        }

        YubihsmUi::display_info_message(&Cmdline, format!("\nAll keys have been exported to {}", dir).as_str())?;

        Ok(())
    }
}