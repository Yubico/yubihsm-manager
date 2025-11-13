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
use crate::utils::print_menu_headers;
use crate::backend::asym::AsymOps;
use crate::backend::object_ops::Importable;
use crate::backend::types::{ImportObjectSpec, ObjectSpec, YhCommand};
use crate::backend::auth::AuthOps;
use crate::backend::object_ops::{Deletable, Obtainable};
use crate::utils::{list_objects, print_failed_delete, print_object_properties, select_delete_objects, fill_object_spec, select_command};
use crate::error::MgmError;
use crate::utils::{get_password,
                   select_capabilities,
                   get_file_path, read_pem_from_file};
use crate::backend::common::{get_delegated_capabilities};
use crate::backend::auth::{AuthenticationType, UserType};

static AUTH_HEADER: &str = "Authentication keys";

pub fn exec_auth_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {
        print_menu_headers(&[crate::MAIN_HEADER, AUTH_HEADER]);

        let cmd = select_command(&AuthOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, AUTH_HEADER, cmd.label]);

        let res = match cmd.command {
            YhCommand::List => list(session),
            YhCommand::GetKeyProperties => print_key_properties(session),
            YhCommand::Delete => delete(session),
            YhCommand::SetupUser => create_authkey(session, authkey, UserType::AsymUser),
            YhCommand::SetupAdmin => create_authkey(session, authkey, UserType::AsymAdmin),
            YhCommand::SetupAuditor => create_authkey(session, authkey, UserType::Auditor),
            YhCommand::SetupBackupAdmin => create_authkey(session, authkey, UserType::BackupAdmin),
            YhCommand::ReturnToMainMenu => return Ok(()),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(err) = res {
            cliclack::log::error(err)?;
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    list_objects(&AuthOps.get_all_objects(session)?)
}

fn print_key_properties(session: &Session) -> Result<(), MgmError> {
    print_object_properties(&AuthOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = select_delete_objects(&AuthOps.get_all_objects(session)?)?;
    let failed = AuthOps.delete_multiple(session, &objects);
    print_failed_delete(&failed)
}

fn create_authkey(
    session: &Session,
    current_authkey: &ObjectDescriptor,
    user_type: UserType
) -> Result<(), MgmError> {

    let mut new_spec = setup_user(current_authkey, user_type)?;
    let mut new_import_spec = ImportObjectSpec::empty();

    let auth_type = cliclack::select("Select authentication type:")
        .item(AuthenticationType::PasswordDerived, "Password derived", "Session keys are derived from a password")
        .item(AuthenticationType::Ecp256, "EC P256", "Session authenticated using EC key with curve secp256r1")
        .interact()?;

    let mut new_key_note = new_spec.to_string();

    match auth_type {
        AuthenticationType::PasswordDerived => {
            new_spec.algorithm = ObjectAlgorithm::Aes128YubicoAuthentication;
            new_key_note = new_key_note.replace("Algorithm: Unknown", "Authentication Type: Password Derived");

            let pwd = get_password("Enter user password:")?;
            new_import_spec.data.push(pwd.as_bytes().to_vec());
        },
        AuthenticationType::Ecp256 => {
            new_spec.algorithm = ObjectAlgorithm::Ecp256YubicoAuthentication;
            new_key_note = new_key_note.replace("Algorithm: Unknown", "Authentication Type: Asymmetric");

            loop {
                let pubkey = read_pem_from_file(get_file_path("Enter path to ECP256 public key PEM file: ")?)?;

                let (_type, _algo, _value) = AsymOps::parse_asym_pem(pubkey)?;
                if _type == ObjectType::PublicKey && _algo == ObjectAlgorithm::EcP256 {
                    new_import_spec.data.push(_value);
                    break;
                }
                cliclack::log::info(
                    "Invalid public key. Found object is either not a public key or not of curve secp256r1. Please try again or press ESC to go back to menu")?;
            }
        }
    };
    new_import_spec.object = new_spec;

    cliclack::note("Creating new authentication key with:", new_key_note)?;
    if cliclack::confirm("Create key?").interact()? {
        let id = AuthOps.import(session, &new_import_spec)?;
        cliclack::log::success(format!("Created new authentication key with ID 0x{id:04x}"))?;
    }
    Ok(())
}

fn setup_user(current_authkey: &ObjectDescriptor, user_type: UserType) -> Result<ObjectSpec, MgmError> {
    let mut new_key = ObjectSpec::empty();
    match user_type {
        UserType::AsymUser =>
            fill_object_spec(current_authkey, &mut new_key, &AuthOps::KEY_USER_CAPABILITIES, &AuthOps::KEY_USER_CAPABILITIES)?,
        UserType::AsymAdmin => {
            fill_object_spec(
                current_authkey, &mut new_key, &AuthOps::KEY_ADMIN_CAPABILITIES, &[])?;
            new_key.delegated_capabilities = select_capabilities(
                "Select delegated capabilities", current_authkey, &AuthOps::KEY_USER_CAPABILITIES, &[])?;
        },
        UserType::Auditor => fill_object_spec(
            current_authkey, &mut new_key, &AuthOps::AUDITOR_CAPABILITIES, &[ObjectCapability::GetLogEntries])?,
        UserType::BackupAdmin => {
            let current_authkey_delegated = get_delegated_capabilities(current_authkey);
            fill_object_spec(
                current_authkey, &mut new_key, current_authkey_delegated.as_slice(), current_authkey_delegated.as_slice())?;
            new_key.delegated_capabilities = select_capabilities(
                "Select delegated capabilities", current_authkey, current_authkey_delegated.as_slice(), current_authkey_delegated.as_slice())?;
        },
    };
    Ok(new_key)
}