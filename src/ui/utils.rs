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

use std::fs::File;
use std::fs;
use std::path::Path;
use std::io::Write;
use pem::Pem;
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::backend::types::NewObjectSpec;
use crate::traits::backend_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::backend::error::MgmError;
use crate::backend::types::MgmCommand;

static ESC_HELP_TEXT: &str = "You can always press 'Esc' to cancel current operation and return to previous menu";

pub fn display_menu_headers(ui: &impl YubihsmUi, menu_headers:&[&str], description: &str) -> Result<(), MgmError> {
    if menu_headers.last() == Some(&MgmCommand::EXIT_COMMAND.label) {
        return Ok(());
    }
     let headers = menu_headers.join(" > ");
    ui.display_note(
        headers.as_str(), format!("{} \n{}", description, ESC_HELP_TEXT).as_str())?;
    Ok(())
}

pub fn get_string_or_bytes_from_file(ui: &impl YubihsmUi, string: String) -> Result<Vec<u8>, MgmError> {
    if string.is_empty() {
        return Ok(vec![])
    }

    match get_bytes_from_file(ui, &string) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(string.as_bytes().to_vec())
    }
}

pub fn get_hex_or_bytes_from_file(ui: &impl YubihsmUi, string: String) -> Result<Vec<u8>, MgmError> {
    if string.is_empty() {
        return Ok(vec![])
    }

    match get_bytes_from_file(ui, &string) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(hex::decode(string)?)
    }
}

pub fn get_bytes_from_file(ui: &impl YubihsmUi, filepath: &String) -> Result<Vec<u8>, MgmError> {
    if Path::new(filepath).exists() {
        ui.display_info_message(
            format!("Read bytes from file: {}", filepath).as_str())?;
        return Ok(fs::read(filepath)?)
    }
    Err(MgmError::InvalidInput("File does not exist".to_string()))
}

pub fn get_pem_from_file(file_path: &String) -> Result<Vec<Pem>, MgmError> {
    let content = fs::read_to_string(file_path)?;
    Ok(pem::parse_many(content)?)
}

pub fn write_bytes_to_file(ui: &impl YubihsmUi, content: &[u8], filename: &str, directory: Option<&str>) -> Result<(), MgmError> {
    let dir = if let Some(d) = directory { d.to_owned() } else { ".".to_owned() };
    let filepath = format!("{}/{}", dir, filename);

    let mut file = match File::options().create_new(true).write(true).open(&filepath) {
        Ok(f) => f,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                if ui.get_confirmation(format!("File {} already exist. Overwrite it?", &filepath).as_str())? {
                    fs::remove_file(&filepath)?;
                    File::options().create_new(true).write(true).open(&filepath)?
                } else {
                    return Ok(())
                }
            } else {
                return Err(MgmError::StdIoError(error))
            }
        }
    };
    file.write_all(content)?;
    ui.display_success_message(format!("Wrote file {}", &filepath).as_str())?;
    Ok(())
}

pub fn list_objects(ui: &impl YubihsmUi, yh_operation: &dyn YubihsmOperations, session: &Session) -> Result<(), MgmError> {
    ui.display_objects_basic(&yh_operation.get_all_objects(session)?)
}

pub fn display_object_properties(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations, session: &Session) -> Result<(), MgmError> {
    let key = ui.select_one_object(
        &yh_operation.get_all_objects(session)?,
        Some("Select key:"))?;
    ui.display_objects_full(&[key])
}

pub fn delete_objects(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations, session: &Session, available_objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
    let objects = ui.select_multiple_objects(
        available_objects,
        false,
        Some("Select key(s) to delete"))?;
    if objects.is_empty() {
        ui.display_info_message("No objects were selected")?;
        return Ok(());
    }

    if !ui.get_warning_confirmation(
        "Selected object(s) will be deleted and cannot be recovered")? {
        ui.display_info_message("Objects are not deleted")?;
        return Ok(());
    }

    for object in objects {
        match yh_operation.delete(session, object.id, object.object_type) {
            Ok(_) => {
                ui.display_success_message(
                    format!("Successfully deleted {} object with ID 0x{:04x} from the YubiHSM", object.object_type, object.id).as_str())?;
            },
            Err(err) => {
                ui.display_error_message(format!("Failed to delete {} object with ID 0x{:04x}. {}", object.object_type, object.id, err).as_str())?;
            }
        }
    }
    Ok(())
}

pub fn generate_object(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations,
                session: &Session,
                authkey: &ObjectDescriptor,
                object_type: ObjectType) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = object_type;
    new_key.algorithm = ui.select_algorithm(
        &yh_operation.get_generation_algorithms(),
        None,
        Some("Select key algorithm"))?;
    new_key.id = ui.get_new_object_id(0)?;
    new_key.label = ui.get_object_label("")?;
    new_key.domains = ui.select_object_domains(&authkey.domains)?;
    new_key.capabilities = ui.select_object_capabilities(
        &yh_operation.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
        &[],
        None)?;

    if !ui.get_note_confirmation("Generating asymmetric key with:", &new_key.to_string())? {
        ui.display_info_message("Key is not generated")?;
        return Ok(());
    }

    let spinner = ui.start_spinner(Some("Generating key..."));
    new_key.id = yh_operation.generate(session, &new_key)?;
    ui.stop_spinner(spinner, None);
    ui.display_success_message(
        format!("Generated asymmetric keypair with ID 0x{:04x} on the YubiHSM", new_key.id).as_str())?;
    Ok(())
}

pub fn import_object(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations,
              session: &Session,
              authkey: &ObjectDescriptor, object_type: ObjectType, object_algorithm: ObjectAlgorithm, data: Vec<Vec<u8>>) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::empty();
    new_key.object_type = object_type;
    new_key.algorithm = object_algorithm;
    new_key.data.extend(data);

    new_key.id = ui.get_new_object_id(0)?;
    new_key.label = ui.get_object_label("")?;
    new_key.domains = ui.select_object_domains(&authkey.domains)?;
    new_key.capabilities = ui.select_object_capabilities(
        &yh_operation.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
        &[],
        Some("Select object capabilities"))?;

    if !ui.get_note_confirmation(
        "Importing asymmetric object with:",
        &new_key.to_string())? {
        ui.display_info_message("Object is not imported")?;
        return Ok(());
    }

    let spinner = ui.start_spinner(Some("Generating key..."));
    new_key.id = yh_operation.import(session, &new_key)?;
    ui.stop_spinner(spinner, None);
    ui.display_success_message(
        format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object_type, new_key.id).as_str())?;
    Ok(())
}