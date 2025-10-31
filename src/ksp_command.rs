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

use yubihsmrs::object::{ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::ksp_utils;
use crate::backend::wrap_utils;
use crate::error::MgmError;
use crate::utils::{get_directory, select_domains, get_id, get_password};
use crate::wrap_commands::{get_shares, get_threshold, object_to_file, wrapkey_shares_display};

pub fn guided_ksp_setup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    cliclack::log::info("This guided setup will help you configure the YubiHSM for KSP use case.")?;
    cliclack::log::info("You will be prompted to enter values for the wrap key and authentication keys.")?;
    cliclack::log::info("Please ensure you have the necessary permissions and that you record the wrap key shares securely.")?;
    cliclack::log::info("Let's begin the setup process.")?;

    ksp_utils::check_privileges(authkey)?;
    let rsa_decrypt = cliclack::confirm("Add RSA decryption capabilities?").interact()?;

    cliclack::log::step("Importing KSP wrap key...")?;
    let id = get_id()?;
    let domains = select_domains(&authkey.domains)?;
    let shares = get_shares()?;
    let threshold = get_threshold(shares)?;
    let (wrapkey_id, wrapkey_shares) = ksp_utils::import_ksp_wrapkey(
        session, id, &domains, rsa_decrypt, shares, threshold)?;
    cliclack::log::success(format!("Successfully imported wrap key with ID  0x{:04x}", wrapkey_id))?;
    loop {
        if cliclack::confirm("Ready to record wrap key shares? ").interact()? {
            break;
        }
    }
    wrapkey_shares_display(wrapkey_shares.shares)?;
    cliclack::log::step("All key shares have been recorded and cannot be displayed again")?;

    cliclack::log::step("Importing application authentication key...")?;
    let appkey_desc = crate::backend::ksp_utils::import_app_authkey(
        session,
        get_id()?,
        &domains,
        rsa_decrypt,
        get_password("Enter application authentication key password:")?,
    )?;
    cliclack::log::success(format!("Successfully imported application authentication key with ID  0x{:04x}", appkey_desc.id))?;

    let auditkey_desc =
        if cliclack::confirm("Create an audit key? ").interact()? {
            cliclack::log::step("Importing audit key...")?;
            let auditkey = crate::backend::ksp_utils::import_audit_authkey(
                session,
                get_id()?,
                &domains,
                get_password("Enter audit key password:")?,
            )?;
            cliclack::log::success(format!("Successfully imported audit key with ID  0x{:04x}", auditkey.id))?;
            auditkey
        } else {
            ObjectDescriptor::new()
        };

    if cliclack::confirm("Export keys? ").interact()? {
        export_keys(session, wrapkey_id, appkey_desc, if auditkey_desc.id != 0 { Some(auditkey_desc) } else { None })?;
    }

    cliclack::log::step("KSP setup completed successfully!")?;

    Ok(())
}

pub fn full_ksp_setup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError>{
    let rsa_decrypt = cliclack::confirm("Add RSA decryption capabilities?").interact()?;

    cliclack::log::step("Enter values for wrap key:")?;
    let id = get_id()?;
    let domains = select_domains(&authkey.domains)?;
    cliclack::log::info("The wrap key will be split into shares. Please enter the number of shares and the threshold for reconstruction.")?;
    let shares = get_shares()?;
    let threshold = get_threshold(shares)?;
    let wrap_key = ksp_utils::KspWrapKeyInput {
        id,
        domains,
        shares,
        threshold,
    };

    // Create an authentication key for usage with the above wrap key
    cliclack::log::step("Enter values for application authentication key:")?;
    let app_key = ksp_utils::KspAuthKeyInput {
        id: get_id()?,
        password: get_password("Enter application authentication key password:")?,
    };

    let audit_key =
        if cliclack::confirm("Create an audit key? ").interact()? {
            cliclack::log::step("Enter values for audit key:")?;
            Some(ksp_utils::KspAuthKeyInput {
                id: get_id()?,
                password: get_password("Enter audit key password:")?,
            })
        } else {
            None
        };




    let ksp_setup= crate::backend::ksp_utils::setup_ksp(
        session,
        authkey,
        rsa_decrypt,
        &wrap_key,
        &app_key,
        audit_key, /* std::option::Option<backend::ksp_utils::KspAuthKeyInput> */
    )?;

    cliclack::log::success(format!(
        "\nKSP setup completed successfully!\n\
        Created wrap key with ID: 0x{:04x}\n\
        Created application authentication Key with ID: 0x{:04x}\
        {}",
        ksp_setup.wrapkey_id,
        ksp_setup.appkey_desc.id,
        if ksp_setup.auditkey_desc.is_some() {
            format!("\nCreated audit key with ID: 0x{:04x}", ksp_setup.auditkey_desc.clone().unwrap().id)
        } else {
            "".to_string()
        }
    ))?;

    cliclack::log::step("Please be prepared to record wrap key shares")?;
    loop {
        if cliclack::confirm("Ready to record wrap key shares? ").interact()? {
            break;
        }
    }
    wrapkey_shares_display(ksp_setup.wrapkey.shares)?;

    cliclack::log::step("All key shares have been recorded and cannot be displayed again")?;

    if cliclack::confirm("Export keys? ").interact()? {
        export_keys(session, ksp_setup.wrapkey_id, ksp_setup.appkey_desc, ksp_setup.auditkey_desc)?;
    }

    if cliclack::confirm("Delete the current authentication key (strongly recommended)?").interact()? {
        session.delete_object(authkey.id, ObjectType::AuthenticationKey)?;
    }

    Ok(())
}

fn export_keys(session: &Session, wrapkey_id: u16, app_desc: ObjectDescriptor, audit_desc: Option<ObjectDescriptor>) -> Result<(), MgmError> {
        let dir = get_directory("Enter export destination directory:")?;

        let wrapped_authkey = wrap_utils::export_wrapped(session, wrapkey_id, &vec![app_desc])?;
        object_to_file(&dir.clone(), wrapped_authkey[0].object_id, ObjectType::AuthenticationKey, &wrapped_authkey[0].wrapped_data)?;

        if audit_desc.is_some() {
            let wrapped_auditkey = wrap_utils::export_wrapped(session, wrapkey_id, &vec![audit_desc.unwrap()])?;
            object_to_file(&dir, wrapped_auditkey[0].object_id, ObjectType::AuthenticationKey, &wrapped_auditkey[0].wrapped_data)?;
        }
        cliclack::log::step(format!("\nAll keys have been exported to {}", dir))?;
    Ok(())
}
