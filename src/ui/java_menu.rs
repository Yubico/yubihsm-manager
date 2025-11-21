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
use crate::ui::utils::{display_menu_headers, display_object_properties, get_pem_from_file};
use crate::cmd_ui::cmd_ui::Cmdline;
use crate::traits::backend_traits::YubihsmOperations;
use crate::backend::error::MgmError;
use crate::backend::types::{MgmCommandType, NewObjectSpec};
use crate::backend::asym::{AsymOps, JavaOps};


static JAVA_HEADER: &str = "SunPKCS11 keys";

pub fn exec_java_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        display_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER],
            "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate are store in the device with the same ObjectID")?;

        let cmd = YubihsmUi::select_command(&Cmdline, &JavaOps.get_authorized_commands(authkey))?;
        display_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER, cmd.label], cmd.description)?;

        let res = match cmd.command {
            MgmCommandType::List => list(session),
            MgmCommandType::GetKeyProperties => dislpay_key_properties(session),
            MgmCommandType::Generate => generate(session, authkey),
            MgmCommandType::Import => import(session, authkey),
            MgmCommandType::Delete => delete(session),
            //MgmCommandType::ReturnToMainMenu => return Ok(()),
            MgmCommandType::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            YubihsmUi::display_error_message(&Cmdline, e.to_string().as_str())?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    YubihsmUi::display_objects_basic(&Cmdline, &JavaOps.get_all_objects(session)?)
}

fn dislpay_key_properties(session: &Session) -> Result<(), MgmError> {
    display_object_properties(&JavaOps.get_all_objects(session)?)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let objects = YubihsmUi::select_multiple_objects(
        &Cmdline,
        &JavaOps.get_all_objects(session)?,
        false,
        Some("Select key(s) to delete"))?;
    if objects.is_empty() {
        YubihsmUi::display_info_message(&Cmdline, "No objects were selected")?;
        return Ok(());
    }

    if !YubihsmUi::get_warning_confirmation(
        &Cmdline, "Selected object(s) will be deleted and cannot be recovered")? {
        YubihsmUi::display_info_message(&Cmdline, "Objects are not deleted")?;
        return Ok(());
    }

    for object in objects {
        match JavaOps.delete(session, object.id, object.object_type) {
            Ok(_) => {
                YubihsmUi::display_success_message(
                    &Cmdline,
                    format!("Successfully deleted asymmetric key and X509Certificate objects with ID 0x{:04x} from the YubiHSM", object.id).as_str())?;
            },
            Err(err) => {
                YubihsmUi::display_error_message(
                    &Cmdline,
                    format!("Failed to delete asymmetric key and/or X509Certificate object with ID 0x{:04x}. {}", object.id, err).as_str())?;
            }
        }
    }
    Ok(())
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = ObjectType::AsymmetricKey;
    new_key.algorithm = YubihsmUi::select_algorithm(
        &Cmdline,
        &JavaOps.get_generation_algorithms(),
        None,
        Some("Select algorithm for the new SunPKCS11 compatible key"))?;

    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &JavaOps.get_applicable_capabilities(authkey, None,Some(new_key.algorithm))?,
        &[],
        None)?;

    if !YubihsmUi::get_note_confirmation(&Cmdline, "Generating SunPKCS11 compatible key with:", &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Key is not generated")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.id = JavaOps.generate(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Generated asymmetric key and stored attestation certificate with ID 0x{:04x} on the YubiHSM", new_key.id).as_str())?;
    Ok(())
}

pub fn import(session: &Session, authkey: &ObjectDescriptor ) -> Result<(), MgmError> {

    let filepath = YubihsmUi::get_pem_filepath(
        &Cmdline,
        "Enter absolute path to PEM file containing private key and/or X509Certificate (Only the first object of its type will be imported):",
        true,
        None)?;
    let mut pems = get_pem_from_file(&filepath)?;

    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = ObjectType::AsymmetricKey;

    loop {
        if let Ok((_algo, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::AsymmetricKey) {
            new_key.algorithm = _algo;
            new_key.data.push(_value);
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
        if let Ok((_, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::Opaque) {
            new_key.data.push(_value);
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

    new_key.id = YubihsmUi::get_new_object_id(&Cmdline, 0)?;
    new_key.label = YubihsmUi::get_object_label(&Cmdline, "")?;
    new_key.domains = YubihsmUi::select_object_domains(&Cmdline, &authkey.domains)?;
    new_key.capabilities = YubihsmUi::select_object_capabilities(
        &Cmdline,
        &AsymOps.get_applicable_capabilities(authkey, None, Some(new_key.algorithm))?,
        &[],
        Some("Select object capabilities"))?;

    if !YubihsmUi::get_note_confirmation(
        &Cmdline,
        "Importing SunPKCS11 compatible key with:",
        &new_key.to_string())? {
        YubihsmUi::display_info_message(&Cmdline, "Object is not imported")?;
        return Ok(());
    }

    let spinner = YubihsmUi::start_spinner(&Cmdline, Some("Generating key..."));
    new_key.id = JavaOps.import(session, &new_key)?;
    YubihsmUi::stop_spinner(&Cmdline, spinner, None);
    YubihsmUi::display_success_message(&Cmdline,
                                       format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object_type, new_key.id).as_str())?;
    Ok(())
}

fn get_first_object_from_pem(pems:Vec<Pem>, object_type:ObjectType) -> Result<(ObjectAlgorithm, Vec<u8>), MgmError> {
    for pem in pems {
        let (_type, _algo, _value) = AsymOps::parse_asym_pem(pem)?;
        if _type == object_type {
            return Ok((_algo, _value));
        }
    }
    Err(MgmError::Error(format!("No object of type {} found in PEM file", object_type)))
}