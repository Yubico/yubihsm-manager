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

use tabled::{builder::Builder, settings::{Width, Modify, Style, object::Columns}};
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::{MgmCommand, NewObjectSpec};
use crate::hsm_operations::common::get_delegated_capabilities;


static ESC_HELP_TEXT: &str = "Pressing 'Esc' will always cancel current operation and return to previous menu";

pub fn display_menu_headers(ui: &impl YubihsmUi, menu_headers:&[&str], description: &str) -> Result<(), MgmError> {
    if menu_headers.last() == Some(&MgmCommand::EXIT_COMMAND.label) {
        return Ok(());
    }
     let headers = menu_headers.join(" > ");
    ui.display_note(
        headers.as_str(), format!("{} \n{}", description, ESC_HELP_TEXT).as_str());
    Ok(())
}

pub fn list_objects(ui: &impl YubihsmUi, yh_operation: &dyn YubihsmOperations, session: &Session) -> Result<(), MgmError> {
    ui.display_objects_list(&yh_operation.get_all_objects(session)?);
    Ok(())
}

pub fn get_new_spec_table(object: &NewObjectSpec) -> String {

    let mut builder = Builder::default();
    builder.push_record(vec![format!("{:24}", "ID").as_str(), format!("0x{:04x?}", object.id).as_str()]);
    builder.push_record(vec!["Type", object.object_type.to_string().as_str()]);
    builder.push_record(vec!["Label", object.label.to_string().as_str()]);
    builder.push_record(vec!["Algorithm", object.algorithm.to_string().as_str()]);
    builder.push_record(vec!["Domains", object.get_domains_str().as_str()]);
    builder.push_record(vec!["Capabilities", object.get_capabilities_str().as_str()]);
    if [ObjectType::AuthenticationKey, ObjectType::WrapKey, ObjectType::PublicWrapKey].contains(&object.object_type) {
        builder.push_record(vec!["Delegated capabilities", object.get_delegated_capabilities_str().as_str()]);
    }
    let mut table = builder.build();
    table.with(Style::modern());

    if let Ok((terminal_width, _)) = crossterm::terminal::size() {
        if terminal_width < 30 {
            return table.to_string();
        }
        let table_width = (terminal_width as f32 * 0.8) as usize;
        table.with(Width::increase(table_width));

        // table.with(tabled::settings::Width::increase(tabled::settings::measurement::Percent(80)));
        table.with(Modify::new(Columns::new(1..))
            .with(Width::wrap(table_width - 24).keep_words()));
    }
    table.to_string()
}

pub fn display_object_properties(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations, session: &Session) -> Result<(), MgmError> {
    let key = ui.select_one_object(
        &yh_operation.get_all_objects(session)?,
        Some("Select key:"))?;
    ui.display_objects_properties(&[key]);
    Ok(())
}

pub fn delete_objects(ui: &impl YubihsmUi,yh_operation: &dyn YubihsmOperations, session: &Session, available_objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
    let objects = ui.select_multiple_objects(
        available_objects,
        false,
        Some("Select key(s) to delete"))?;
    if objects.is_empty() {
        ui.display_info_message("No objects were selected");
        return Ok(());
    }

    if !ui.get_warning_confirmation(
        "Selected object(s) will be deleted and cannot be recovered")? {
        ui.display_info_message("Objects are not deleted");
        return Ok(());
    }

    for object in objects {
        match yh_operation.delete(session, object.id, object.object_type) {
            Ok(_) => {
                ui.display_success_message(
                    format!("Successfully deleted {} object with ID 0x{:04x} from the YubiHSM", object.object_type, object.id).as_str());
            },
            Err(err) => {
                ui.display_error_message(format!("Failed to delete {} object with ID 0x{:04x}. {}", object.object_type, object.id, err).as_str());
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

    if object_type == ObjectType::WrapKey {
        new_key.delegated_capabilities = ui.select_object_capabilities(
            &get_delegated_capabilities(authkey),
            &get_delegated_capabilities(authkey),
            Some("Select delegated capabilities"))?;
    }

    if !ui.get_note_confirmation("Generating asymmetric key with:", &get_new_spec_table(&new_key))? {
        ui.display_info_message("Key is not generated");
        return Ok(());
    }

    let progress = ui.start_progress(Some("Generating key..."));
    new_key.id = yh_operation.generate(session, &new_key)?;
    ui.stop_progress(progress, None);
    ui.display_success_message(
        format!("Generated asymmetric keypair with ID 0x{:04x} on the YubiHSM", new_key.id).as_str());
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
        &get_new_spec_table(&new_key))? {
        ui.display_info_message("Object is not imported");
        return Ok(());
    }

    let progress = ui.start_progress(Some("Generating key..."));
    new_key.id = yh_operation.import(session, &new_key)?;
    ui.stop_progress(progress, None);
    ui.display_success_message(
        format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object_type, new_key.id).as_str());
    Ok(())
}