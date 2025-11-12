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
use crate::backend::ksp::KspOps;
use crate::backend::wrap;
use crate::backend::wrap::{WrapKeyType, WrapOps, WrapType};
use crate::utils::write_bytes_to_file;
use crate::error::MgmError;
use crate::utils::{get_directory, get_id, get_password, select_domains};
use crate::wrap_commands::{display_wrapkey_shares, get_shares, get_threshold};

pub fn guided_ksp_setup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    cliclack::log::info("This guided setup will help you configure the YubiHSM for KSP use case.")?;
    cliclack::log::info("You will be prompted to enter values for the wrap key and authentication keys.")?;
    cliclack::log::info("Please ensure you have the necessary permissions and that you record the wrap key shares securely.")?;
    cliclack::log::info("Let's begin the setup process.")?;

    KspOps::check_privileges(authkey)?;
    let rsa_decrypt = cliclack::confirm("Add RSA decryption capabilities?").interact()?;

    cliclack::log::step("Importing KSP wrap key...")?;
    let id = get_id()?;
    let domains = select_domains(&authkey.domains)?;
    let shares = get_shares()?;
    let threshold = get_threshold(shares)?;
    let (wrapkey_id, wrapkey_shares) = KspOps::import_ksp_wrapkey(
        session, id, &domains, rsa_decrypt, shares, threshold)?;
    cliclack::log::success(format!("Successfully imported wrap key with ID  0x{:04x}", wrapkey_id))?;
    loop {
        if cliclack::confirm("Ready to record wrap key shares? ").interact()? {
            break;
        }
    }
    display_wrapkey_shares(wrapkey_shares.shares_data)?;
    cliclack::log::step("All key shares have been recorded and cannot be displayed again\n")?;

    cliclack::log::step("Importing application authentication key...")?;
    let appkey_desc = KspOps::import_app_authkey(
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
            let auditkey = KspOps::import_audit_authkey(
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

    if cliclack::confirm("Delete the current authentication key (strongly recommended)?").interact()? {
        session.delete_object(authkey.id, ObjectType::AuthenticationKey)?;
    }

    Ok(())
}

pub fn full_ksp_setup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError>{
    let rsa_decrypt = cliclack::confirm("Add RSA decryption capabilities?").interact()?;
    let domains = select_domains(&authkey.domains)?;

    cliclack::log::step("Enter values for wrap key:")?;
    let wrap_id = get_id()?;
    cliclack::log::info("The wrap key will be split into shares. Please enter the number of shares and the threshold for reconstruction.")?;
    let shares = get_shares()?;
    let threshold = get_threshold(shares)?;

    // Create an authentication key for usage with the above wrap key
    cliclack::log::step("Enter values for application authentication key:")?;
    let appkey_id = get_id()?;
    let appkey_pwd = get_password("Enter application authentication key password:")?;

    let (audit_id, audit_pwd) =
        if cliclack::confirm("Create an audit key? ").interact()? {
            cliclack::log::step("Enter values for audit key:")?;
            (Some(get_id()?), Some(get_password("Enter audit key password:")?))
        } else {
            (None, None)
        };

    let ksp_setup= KspOps::setup_ksp(
        session,
        authkey,
        false,
        rsa_decrypt,
        &domains,
        wrap_id,
        threshold,
        shares,
        appkey_id,
        appkey_pwd,
        audit_id,
        audit_pwd,
    )?;

    cliclack::log::success(format!(
        "\nKSP setup completed successfully!\n\
        Created wrap key with ID: 0x{:04x}\n\
        Created application authentication Key with ID: 0x{:04x}\
        {}",
        ksp_setup.wrapkey_id,
        ksp_setup.appkey.id,
        if ksp_setup.auditkey.is_some() {
            format!("\nCreated audit key with ID: 0x{:04x}", ksp_setup.auditkey.clone().unwrap().id)
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
    display_wrapkey_shares(ksp_setup.wrapkey.shares_data)?;

    cliclack::log::step("All key shares have been recorded and cannot be displayed again")?;

    if cliclack::confirm("Export keys? ").interact()? {
        export_keys(session, ksp_setup.wrapkey_id, ksp_setup.appkey, ksp_setup.auditkey)?;
    }

    if cliclack::confirm("Delete the current authentication key (strongly recommended)?").interact()? {
        session.delete_object(authkey.id, ObjectType::AuthenticationKey)?;
    }

    Ok(())
}

fn export_keys(session: &Session, wrapkey_id: u16, appkey: ObjectDescriptor, auditkey: Option<ObjectDescriptor>) -> Result<(), MgmError> {
    let dir = get_directory("Enter export destination directory:")?;

    let mut export_objects = vec![appkey];
    if let Some(key) = auditkey {
        export_objects.push(key);
    }

    let wrap_op_spec = wrap::WrapOpSpec {
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
        write_bytes_to_file(base64::encode_block(&key.wrapped_data).as_bytes(), &dir, filename.as_str())?;
    }

    cliclack::log::step(format!("\nAll keys have been exported to {}", dir))?;

    Ok(())
}
