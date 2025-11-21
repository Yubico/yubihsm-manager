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
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::ui::utils::{delete_objects, display_object_properties, get_pem_from_file, display_menu_headers};
use crate::backend::error::MgmError;
use crate::backend::asym::AsymOps;
use crate::backend::types::{NewObjectSpec, MgmCommandType, SelectionItem};
use crate::backend::common::get_delegated_capabilities;
use crate::backend::auth::{AuthOps, AuthenticationType, UserType};

static AUTH_HEADER: &str = "Authentication keys";

pub fn exec_auth_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        display_menu_headers(&[crate::MAIN_HEADER, AUTH_HEADER],
                             "Authentication key operations allow you to setup users by managing authentication keys stored on the YubiHSM")?;

        let cmd = YubihsmUi::select_command(
            &Cmdline, &AuthOps.get_authorized_commands(authkey))?;
        display_menu_headers(&[crate::MAIN_HEADER, AUTH_HEADER, cmd.label], cmd.description)?;

        let res = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => print_key_properties(session),
            MgmCommandType::Delete => delete(session),
            MgmCommandType::SetupUser => create_authkey(session, authkey, UserType::AsymUser),
            MgmCommandType::SetupAdmin => create_authkey(session, authkey, UserType::AsymAdmin),
            MgmCommandType::SetupAuditor => create_authkey(session, authkey, UserType::Auditor),
            MgmCommandType::SetupBackupAdmin => create_authkey(session, authkey, UserType::BackupAdmin),
            MgmCommandType::ReturnToMainMenu => return Ok(()),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(err) = res {
            YubihsmUi::display_error_message(&Cmdline, err.to_string().as_str())?;
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    YubihsmUi::display_objects_basic(&Cmdline, &AuthOps.get_all_objects(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&AuthOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    delete_objects(session, &AuthOps.get_all_objects(session)?)
}

fn create_authkey(
    session: &Session,
    current_authkey: &ObjectDescriptor,
    user_type: UserType
) -> Result<(), MgmError> {

    let mut new_key = setup_user(current_authkey, user_type)?;

    let auth_type = YubihsmUi::select_one_item(
        &Cmdline,
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

            let pwd = YubihsmUi::get_password(&Cmdline, "Enter user password:", true)?;
            new_key.data.push(pwd.as_bytes().to_vec());
        },
        AuthenticationType::Ecp256 => {
            new_key.algorithm = ObjectAlgorithm::Ecp256YubicoAuthentication;
            new_key_note = new_key_note.replace("Algorithm: Unknown", "Authentication Type: Asymmetric");

            let pubkey = YubihsmUi::get_public_ecp256_filepath(&Cmdline, "Enter path to ECP256 public key PEM file: ")?;
            let pubkey = get_pem_from_file(&pubkey)?[0].clone();

            let (_type, _algo, _value) = AsymOps::parse_asym_pem(pubkey)?;
            if _type != ObjectType::PublicKey && _algo != ObjectAlgorithm::EcP256 {
                return Err(MgmError::InvalidInput(
                    "Invalid public key. Found object is either not a public key or not of curve secp256r1.".to_string()));
             }
            new_key.data.push(_value);
        }
    };

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Creating new authentication key with:", &new_key_note)? {
        YubihsmUi::display_info_message(&Cmdline, "Authentication key not created")?;
        return Ok(());
    }

    new_key.id = AuthOps.import(session, &new_key)?;
    YubihsmUi::display_success_message(&Cmdline, format!("Created new authentication key with ID 0x{:04x}", new_key.id).as_str())?;
    Ok(())
}

fn setup_user(current_authkey: &ObjectDescriptor, user_type: UserType) -> Result<NewObjectSpec, MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = ObjectType::AuthenticationKey;
    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &current_authkey.domains)?;
    match user_type {
        UserType::AsymUser =>
            new_key.capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &AuthOps::KEY_USER_CAPABILITIES,
                &AuthOps::KEY_USER_CAPABILITIES,
                None)?,
        UserType::AsymAdmin => {
            new_key.capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &AuthOps::KEY_ADMIN_CAPABILITIES,
                &[],
                None)?;
            new_key.delegated_capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &AuthOps::KEY_USER_CAPABILITIES,
                &[],
                Some("Select delegated capabilities"))?;
        },
        UserType::Auditor =>
            new_key.capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &AuthOps::AUDITOR_CAPABILITIES,
                &[ObjectCapability::GetLogEntries],
                None)?,
        UserType::BackupAdmin => {
            let current_authkey_delegated = get_delegated_capabilities(current_authkey);
            new_key.capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &current_authkey_delegated,
                &current_authkey_delegated,
                None)?;
            new_key.delegated_capabilities = YubihsmUi::select_object_capabilities(
                &Cmdline,
                &current_authkey_delegated,
                &current_authkey_delegated,
                Some("Select delegated capabilities"))?;
        },
    };
    Ok(new_key)
}