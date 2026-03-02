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

use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::ui::helper_operations::{delete_objects, display_object_properties, get_new_spec_table, list_objects};
use crate::ui::helper_operations::{display_menu_headers, get_script_input_data};
use crate::common::error::MgmError;
use crate::common::types::{MgmCommandType, NewObjectSpec, SelectionItem};
use crate::common::util::get_delegated_capabilities;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::auth::{AuthenticationOperations, AuthenticationType, UserType};
use crate::ui::helper_io::get_pem_from_file;
use crate::script::script_recorder::SessionRecorder;
use crate::script::script_types::{RecordableObjectSpec, RecordedOperation};

static AUTH_HEADER: &str = "Authentication keys";

pub struct AuthenticationMenu<T: YubihsmUi> {
    ui: T,
}

impl<T: YubihsmUi> AuthenticationMenu<T> {

    pub fn new(interface: T) -> Self {
        AuthenticationMenu { ui: interface  }
    }

    pub fn exec_command(&self, session: &Session, recorder: &Option<SessionRecorder>, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        loop {
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, AUTH_HEADER],
                                 "Authentication key operations allow you to setup users by managing authentication keys stored on the YubiHSM")?;

            let cmd = self.ui.select_command(
                &AuthenticationOperations.get_authorized_commands(authkey))?;
            display_menu_headers(&self.ui, &[crate::MAIN_HEADER, AUTH_HEADER, cmd.label], cmd.description)?;

            let res = match cmd.command {
                MgmCommandType::List => list_objects(&self.ui, &AuthenticationOperations, session),
                MgmCommandType::GetKeyProperties => display_object_properties(&self.ui, &AuthenticationOperations, session),
                MgmCommandType::Delete => delete_objects(&self.ui, recorder, &AuthenticationOperations, session, &AuthenticationOperations.get_all_objects(session)?),
                MgmCommandType::SetupUser => self.create_authkey(session, recorder, authkey, UserType::KeyUser),
                MgmCommandType::SetupAdmin => self.create_authkey(session, recorder, authkey, UserType::KeyAdmin),
                MgmCommandType::SetupAuditor => self.create_authkey(session, recorder, authkey, UserType::Auditor),
                MgmCommandType::SetupCustomUser => self.create_authkey(session, recorder, authkey, UserType::CustomUser),
                MgmCommandType::Exit => std::process::exit(0),
                _ => unreachable!()
            };

            if let Err(err) = res {
                self.ui.display_error_message(err.to_string().as_str());
            }
        }
    }

    fn create_authkey(&self,
                      session: &Session,
                      recorder: &Option<SessionRecorder>,
                      current_authkey: &ObjectDescriptor,
                      user_type: UserType
    ) -> Result<(), MgmError> {
        let mut new_key = self.setup_user(current_authkey, user_type)?;

        let auth_type = self.ui.select_one_item(
            &[
                SelectionItem {
                    value: AuthenticationType::PasswordDerived,
                    label: "Password derived".to_string(),
                    hint: "Session keys are derived from a password".to_string() },
                SelectionItem {
                    value: AuthenticationType::Ecp256,
                    label: "EC P256".to_string(),
                    hint: "Session authenticated using EC key with curve secp256r1".to_string() },
            ],
            None,
            Some("Select authentication type"))?;

        let mut pubkey_filename:Option<String> = None;
        match auth_type {
            AuthenticationType::PasswordDerived => {
                new_key.algorithm = ObjectAlgorithm::Aes128YubicoAuthentication;

                let pwd = self.ui.get_password("Enter user password:", true)?;
                new_key.data.push(pwd.as_bytes().to_vec());
            },
            AuthenticationType::Ecp256 => {
                new_key.algorithm = ObjectAlgorithm::Ecp256YubicoAuthentication;

                let f = self.ui.get_public_ecp256_filepath("Enter path to ECP256 public key PEM file: ")?;
                let pubkey = get_pem_from_file(&f)?;
                if pubkey.len() > 1 {
                    self.ui.display_warning("Warning!! More than one PEM object found in file. Only the first object is read");
                }
                let pubkey = pubkey[0].clone();
                pubkey_filename = Some(f);

                let (_type, _algo, _value) = AsymmetricOperations::parse_asym_pem(pubkey)?;
                if _type != ObjectType::PublicKey && _algo != ObjectAlgorithm::EcP256 {
                    return Err(MgmError::InvalidInput(
                        "Invalid public key. Found object is either not a public key or not of curve secp256r1.".to_string()));
                }
                new_key.data.push(_value);
            }
        };

        if !self.ui.get_note_confirmation("Creating new authentication key with:", &get_new_spec_table(&new_key))? {

            self.ui.display_info_message("Authentication key not created");
            return Ok(());
        }

        new_key.id = AuthenticationOperations.import(session, &new_key)?;
        self.ui.display_success_message(format!("Created new authentication key with ID 0x{:04x}", new_key.id).as_str());

        if let Some(rec) = recorder {
            let credential = get_script_input_data(&rec.mode, &new_key, pubkey_filename)?;
            rec.record(RecordedOperation::CreateAuthKey { spec: RecordableObjectSpec::from(&new_key), credential })?;
        }

        Ok(())
    }

    fn setup_user(&self, current_authkey: &ObjectDescriptor, user_type: UserType) -> Result<NewObjectSpec, MgmError> {
        let mut new_key = NewObjectSpec::new();
        new_key.object_type = ObjectType::AuthenticationKey;
        new_key.id = self.ui.get_new_object_id(0)?;
        new_key.label = self.ui.get_object_label("")?;
        new_key.domains = self.ui.select_object_domains(&current_authkey.domains)?;
        let applicable_capabilities = AuthenticationOperations::get_applicable_capabilities(current_authkey, user_type);
        new_key.capabilities = self.ui.select_object_capabilities(
            &applicable_capabilities,
            &applicable_capabilities,
            None)?;

        if user_type == UserType::KeyAdmin {
            new_key.delegated_capabilities = self.ui.select_object_capabilities(
                &AuthenticationOperations::get_applicable_capabilities(current_authkey, UserType::KeyUser),
                &[],
                Some("Select delegated capabilities"))?;
        }

        if user_type == UserType::CustomUser {
            let current_authkey_delegated = get_delegated_capabilities(current_authkey);
            new_key.delegated_capabilities = self.ui.select_object_capabilities(
                &current_authkey_delegated,
                &current_authkey_delegated,
                Some("Select delegated capabilities"))?;
        }

        Ok(new_key)
    }
}