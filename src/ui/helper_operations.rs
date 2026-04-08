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

use tabled::{builder::Builder, settings::{Modify, object::Columns, Style, Width}};
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::ui_traits::YubihsmUi;
use crate::common::error::MgmError;
use crate::common::types::{NewObjectSpec, EXIT_LABEL};
use crate::common::util::get_delegated_capabilities;
use crate::script::script_recorder::SessionRecorder;
use crate::script::script_types;
use crate::script::script_types::{RecordableObjectSpec, RecordedOperation, MaskLevel};

static ESC_HELP_TEXT: &str = "Pressing 'Esc' will always cancel current operation and return to previous menu";

pub fn display_menu_headers(ui: &impl YubihsmUi, menu_headers:&[&str], description: &str) -> Result<(), MgmError> {
    if menu_headers.last() == Some(&EXIT_LABEL) {
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

pub fn get_aes_keylen_from_algorithm(object_algorithm: ObjectAlgorithm) -> Result<usize, MgmError> {
    match object_algorithm {
        ObjectAlgorithm::Aes128 | ObjectAlgorithm::Aes128CcmWrap => Ok(16),
        ObjectAlgorithm::Aes192 | ObjectAlgorithm::Aes192CcmWrap => Ok(24),
        ObjectAlgorithm::Aes256 | ObjectAlgorithm::Aes256CcmWrap => Ok(32),
        _ => Err(MgmError::Error(format!("{} is not an AES key algorithm", object_algorithm)))
    }
}

pub fn delete_objects(ui: &impl YubihsmUi, recorder: &Option<SessionRecorder>, yh_operation: &dyn YubihsmOperations, session: &Session, available_objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
    if available_objects.is_empty() {
        ui.display_info_message("No objects available for deletion by this user");
        return Ok(());
    }
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
        match yh_operation.delete(session, object.object_id(), object.object_type()) {
            Ok(_) => {
                ui.display_success_message(
                    format!("Successfully deleted {} object with ID 0x{:04x} from the YubiHSM", object.object_type(), object.object_id()).as_str());

                if let Some(rec) = recorder {
                    rec.record(RecordedOperation::DeleteObject {
                        object_id: object.object_id(),
                        object_type: *object.object_type(),
                        context: yh_operation.context().to_string(),
                    })?;
                }
            },
            Err(err) => {
                ui.display_error_message(format!("Failed to delete {} object with ID 0x{:04x}. {}", object.object_type(), object.object_id(), err).as_str());
            }
        }
    }
    Ok(())
}

pub fn generate_object(ui: &impl YubihsmUi, recorder: &Option<SessionRecorder>, yh_operation: &dyn YubihsmOperations,
                       session: &Session,
                       authkey: &ObjectDescriptor,
                       object_type: ObjectType) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::default();
    new_key.object_type = object_type;
    new_key.algorithm = ui.select_algorithm(
        &yh_operation.get_generation_algorithms(),
        None,
        Some("Select key algorithm"))?;
    new_key.id = ui.get_new_object_id(0)?;
    new_key.label = ui.get_object_label("")?;
    new_key.domains = ui.select_object_domains(&authkey.domains())?;
    new_key.capabilities = ui.select_object_capabilities(
        &yh_operation.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
        None)?;

    if object_type == ObjectType::WrapKey {
        new_key.delegated_capabilities = ui.select_object_capabilities(
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
        format!("Generated object of type {} and ID 0x{:04x} on the YubiHSM", new_key.object_type, new_key.id).as_str());

    if let Some(rec) = recorder {
        rec.record(RecordedOperation::GenerateObject {
            spec: RecordableObjectSpec::from(&new_key),
            context: yh_operation.context().to_string()
        })?;
    }

    Ok(())
}

pub fn import_object(ui: &impl YubihsmUi, recorder: &Option<SessionRecorder>, yh_operation: &dyn YubihsmOperations,
                     session: &Session,
                     authkey: &ObjectDescriptor,
                     object_type: ObjectType,
                     object_algorithm: ObjectAlgorithm,
                     data: Vec<Vec<u8>>,
                    filename: Option<String>) -> Result<(), MgmError> {
    let mut new_key = NewObjectSpec::default();
    new_key.object_type = object_type;
    new_key.algorithm = object_algorithm;
    new_key.data.extend(data);

    new_key.id = ui.get_new_object_id(0)?;
    new_key.label = ui.get_object_label("")?;
    new_key.domains = ui.select_object_domains(&authkey.domains())?;
    new_key.capabilities = ui.select_object_capabilities(
        &yh_operation.get_applicable_capabilities(authkey, Some(new_key.object_type), Some(new_key.algorithm))?,
        Some("Select object capabilities"))?;

    if !ui.get_note_confirmation(
        "Importing asymmetric object with:",
        &get_new_spec_table(&new_key))? {
        ui.display_info_message("Object is not imported");
        return Ok(());
    }

    let progress = ui.start_progress(Some("Importing key..."));
    new_key.id = yh_operation.import(session, &new_key)?;
    ui.stop_progress(progress, None);
    ui.display_success_message(
        format!("Imported {} object with ID 0x{:04x} into the YubiHSM", new_key.object_type, new_key.id).as_str());

    record_import_object_operation(recorder, &new_key, yh_operation.context().to_string(), filename)?;

    Ok(())
}

pub fn get_script_input_data(mask_level: &MaskLevel, new_key: &NewObjectSpec, filename: Option<String>) -> Result<String, MgmError> {
    let data = match mask_level {
        MaskLevel::All | MaskLevel::Sensitive => script_types::PROMPT.to_string(),
        MaskLevel::None => {
            if let Some(filename) = filename {
                filename
            } else {
                hex::encode(&new_key.data[0])
            }
        },
    };
    Ok(data)
}

pub fn record_import_object_operation(recorder: &Option<SessionRecorder>, new_key: &NewObjectSpec, context: String, filename: Option<String>) -> Result<(), MgmError> {
    if let Some(rec) = recorder {
        let data = get_script_input_data(&rec.mask, new_key, filename)?;
        rec.record(RecordedOperation::ImportObject { spec: RecordableObjectSpec::from(new_key), value: data, context })?;
    }
    Ok(())
}

pub fn display_wrapkey_shares(ui: &impl YubihsmUi, shares: Vec<String>) -> Result<(), MgmError> {
    ui.display_warning(
        "*************************************************************\n\
        * WARNING! The following shares will NOT be stored anywhere *\n\
        * Save them and store them safely if you wish to re-use     *\n\
        * the wrap key for this device in the future                *\n\
        *************************************************************");

    ui.get_string_input("Press any key to start saving key shares", false, None, None)?;

    for share in shares {
        loop {
            ui.clear_screen();
            println!("{}", share);
            if ui.get_confirmation("Have you saved the key share?")? {
                break;
            }
        }
        ui.clear_screen();
        ui.get_string_input("Press any key to display next key share or to return to menu", false, None, None)?;
    }

    ui.clear_screen();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::script_types::MaskLevel;
    use crate::common::types::NewObjectSpec;
    use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};

    fn make_spec_with_data(data: Vec<u8>) -> NewObjectSpec {
        let spec = NewObjectSpec {
            id: 0x0001,
            object_type: ObjectType::AsymmetricKey,
            label: "key".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignPkcs],
            delegated_capabilities: vec![],
            data: vec![data],
        };
        spec
    }

    // ════════════════════════════════════════════��═
    //  get_aes_keylen_from_algorithm
    // ══════════════════════════════════════════════

    #[test]
    fn test_aes_keylen() {
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes128).unwrap(), 16);
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes128CcmWrap).unwrap(), 16);
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes192).unwrap(), 24);
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes192CcmWrap).unwrap(), 24);
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes256).unwrap(), 32);
        assert_eq!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes256CcmWrap).unwrap(), 32);
        assert!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Aes128YubicoAuthentication).is_err());
        assert!(get_aes_keylen_from_algorithm(ObjectAlgorithm::Rsa2048).is_err());
    }

    // ══════════════════════════════════════════════
    //  get_script_input_data — masking levels
    // ══════════════════════════════════════════════

    #[test]
    fn test_script_input_data_sensitive_mode_no_filename() {
        let spec = make_spec_with_data(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = get_script_input_data(&MaskLevel::Sensitive, &spec, None).unwrap();
        assert_eq!(result, script_types::PROMPT);
    }

    #[test]
    fn test_script_input_data_sensitive_mode_with_filename() {
        let spec = make_spec_with_data(vec![0xDE, 0xAD]);
        let result = get_script_input_data(&MaskLevel::Sensitive, &spec, Some("/path/to/key.pem".to_string())).unwrap();
        assert_eq!(result, script_types::PROMPT);
    }

    #[test]
    fn test_script_input_data_all_mode() {
        let spec = make_spec_with_data(vec![0xDE, 0xAD]);
        let result = get_script_input_data(&MaskLevel::All, &spec, None).unwrap();
        assert_eq!(result, script_types::PROMPT);
    }

    #[test]
    fn test_script_input_data_none_mode_no_filename() {
        let spec = make_spec_with_data(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = get_script_input_data(&MaskLevel::None, &spec, None).unwrap();
        assert_eq!(result, "deadbeef"); // hex-encoded
    }

    #[test]
    fn test_script_input_data_none_mode_with_filename() {
        let spec = make_spec_with_data(vec![0xDE, 0xAD]);
        let result = get_script_input_data(&MaskLevel::None, &spec, Some("/path/to/key.pem".to_string())).unwrap();
        // When filename is provided in None mode, the filename is returned instead of hex data
        assert_eq!(result, "/path/to/key.pem");
    }

    // ══════════════════════════════════════════════
    //  record_import_object_operation — with None recorder
    // ══════════════════════════════════════════════

    #[test]
    fn test_record_import_none_recorder() {
        let spec = make_spec_with_data(vec![0x01, 0x02]);
        // Should be a no-op when recorder is None
        assert!(record_import_object_operation(&None, &spec, "asym".to_string(), None).is_ok());
    }
}