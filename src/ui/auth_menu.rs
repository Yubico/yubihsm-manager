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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::backend_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::utils::{list_objects, delete_objects, display_object_properties, get_pem_from_file, display_menu_headers};
use crate::backend::error::MgmError;
use crate::backend::asym::AsymOps;
use crate::backend::types::{NewObjectSpec, MgmCommandType, SelectionItem};
use crate::backend::common::get_delegated_capabilities;
use crate::backend::auth::{AuthOps, AuthenticationType, UserType};

static AUTH_HEADER: &str = "Authentication keys";

pub struct AuthenticationMenu<T: YubihsmUi> {
    ui: T,
}

impl<T: YubihsmUi> AuthenticationMenu<T> {

    pub fn new(interface: T) -> Self {
        AuthenticationMenu { ui: interface  }
    }

    pub fn exec_command(&self, session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, AUTH_HEADER],
                                 "Authentication key operations allow you to setup users by managing authentication keys stored on the YubiHSM")?;

            let cmd = self.ui.select_command(
                &AuthOps.get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, AUTH_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &AuthOps, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&self.ui, &AuthOps, session),
                MgmCommandType::Delete => delete_objects(&self.ui, &AuthOps, session, &AuthOps.get_all_objects(session)?),
                MgmCommandType::SetupUser => self.create_authkey(session, authkey, UserType::AsymUser),
                MgmCommandType::SetupAdmin => self.create_authkey(session, authkey, UserType::AsymAdmin),
                MgmCommandType::SetupAuditor => self.create_authkey(session, authkey, UserType::Auditor),
                MgmCommandType::SetupBackupAdmin => self.create_authkey(session, authkey, UserType::BackupAdmin),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(err) = res {
                self.ui.display_error_message(err.to_string().as_str())?;
            }
        }
    }

    fn create_authkey(&self,
                      session: &Session,
                      current_authkey: &ObjectDescriptor,
                      user_type: UserType
    ) -> Result<(), MgmError> {
        let mut new_key = self.setup_user(current_authkey, user_type)?;

        let auth_type = self.ui.select_one_item(
            &[
                SelectionItem::new(AuthenticationType::PasswordDerived, "Password derived".to_string(), "Session keys are derived from a password".to_string()),
                SelectionItem::new(AuthenticationType::Ecp256, "EC P256".to_string(), "Session authenticated using EC key with curve secp256r1".to_string()),
            ],
            None,
            Some("Select authentication type"))?;

        let mut new_key_note = new_key.to_string();

        match auth_type {
            AuthenticationType::PasswordDerived => {
                new_key.algorithm = ObjectAlgorithm::Aes128YubicoAuthentication;
                new_key_note = new_key_note.replace("Algorithm: Unknown", "Authentication Type: Password Derived");

                let pwd = self.ui.get_password("Enter user password:", true)?;
                new_key.data.push(pwd.as_bytes().to_vec());
            },
            AuthenticationType::Ecp256 => {
                new_key.algorithm = ObjectAlgorithm::Ecp256YubicoAuthentication;
                new_key_note = new_key_note.replace("Algorithm: Unknown", "Authentication Type: Asymmetric");

                let pubkey = self.ui.get_public_ecp256_filepath("Enter path to ECP256 public key PEM file: ")?;
                let pubkey = get_pem_from_file(&pubkey)?[0].clone();

                let (_type, _algo, _value) = AsymOps::parse_asym_pem(pubkey)?;
                if _type != ObjectType::PublicKey && _algo != ObjectAlgorithm::EcP256 {
                    return Err(MgmError::InvalidInput(
                        "Invalid public key. Found object is either not a public key or not of curve secp256r1.".to_string()));
                }
                new_key.data.push(_value);
            }
        };

        if !self.ui.get_note_confirmation("Creating new authentication key with:", &new_key_note)? {
            self.ui.display_info_message("Authentication key not created")?;
            return Ok(());
        }

        new_key.id = AuthOps.import(session, &new_key)?;
        self.ui.display_success_message(format!("Created new authentication key with ID 0x{:04x}", new_key.id).as_str())?;
        Ok(())
    }

    fn setup_user(&self, current_authkey: &ObjectDescriptor, user_type: UserType) -> Result<NewObjectSpec, MgmError> {
        let mut new_key = NewObjectSpec::empty();
        new_key.object_type = ObjectType::AuthenticationKey;
        new_key.id = self.ui.get_new_object_id(0)?;
        new_key.label = self.ui.get_object_label("")?;
        new_key.domains = self.ui.select_object_domains(&current_authkey.domains)?;
        match user_type {
            UserType::AsymUser => new_key.capabilities = self.ui.select_object_capabilities(
                &AuthOps::KEY_USER_CAPABILITIES,
                &AuthOps::KEY_USER_CAPABILITIES,
                None)?,
            UserType::AsymAdmin => {
                new_key.capabilities = self.ui.select_object_capabilities(
                    &AuthOps::KEY_ADMIN_CAPABILITIES,
                    &[],
                    None)?;
                new_key.delegated_capabilities = self.ui.select_object_capabilities(
                    &AuthOps::KEY_USER_CAPABILITIES,
                    &[],
                    Some("Select delegated capabilities"))?;
            },
            UserType::Auditor => new_key.capabilities = self.ui.select_object_capabilities(
                &AuthOps::AUDITOR_CAPABILITIES,
                &[ObjectCapability::GetLogEntries],
                None)?,
            UserType::BackupAdmin => {
                let current_authkey_delegated = get_delegated_capabilities(current_authkey);
                new_key.capabilities = self.ui.select_object_capabilities(
                    &current_authkey_delegated,
                    &current_authkey_delegated,
                    None)?;
                new_key.delegated_capabilities = self.ui.select_object_capabilities(
                    &current_authkey_delegated,
                    &current_authkey_delegated,
                    Some("Select delegated capabilities"))?;
            },
        };
        Ok(new_key)
    }
}