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

use std::str::FromStr;
use comfy_table::{ContentArrangement, Table};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain};
use crate::traits::ui_traits::YubihsmUi;
use crate::traits::ui_traits::SpinnerHandler;
use crate::backend::error::MgmError;
use crate::backend::common;
use crate::backend::validators::{pem_private_rsa_file_validator, pem_public_rsa_file_validator};
use crate::backend::validators::{integer_validator, path_exists_validator, aes_share_validator};
use crate::backend::validators::{pem_public_eckey_file_validator, pem_public_ecp256_file_validator};
use crate::backend::validators::{object_id_validator, object_label_validator, pem_file_validator, pem_certificate_file_validator};
use crate::backend::types::{MgmCommand, SelectionItem, ObjectSpec};
use crate::backend::algorithms::MgmAlgorithm;


pub struct Cmdline;

static MULTI_SELECT_PROMPT_HELP: &str = "Press the space button to select and unselect item. Press 'Enter' when done.";

impl YubihsmUi for Cmdline {

    fn get_new_object_id(&self, default: u16) -> Result<u16, MgmError> {
        let id: String = cliclack::input("Enter object ID:")
            .default_input(default.to_string().as_str())
            .placeholder(format!("Default is {} for device generated ID", default).as_str())
            .validate(|input: &String| object_id_validator(input))
            .interact()?;
        common::get_id_from_string(id.as_str())
    }

    fn get_object_id(&self) -> Result<u16, MgmError> {
        let id: String = cliclack::input("Enter object ID:")
            .placeholder("Object ID in range [0, 65535]")
            .validate(|input: &String| object_id_validator(input))
            .interact()?;

        common::get_id_from_string(id.as_str())
    }

    fn get_password(&self, prompt: &str, confirm: bool) -> Result<String, MgmError> {
        let pwd = cliclack::password(prompt)
            .mask('*')
            .interact()?;
        if !confirm {
            return Ok(pwd);
        }

        let pwd_clone = pwd.clone();
        cliclack::password("Re-enter password")
            .mask('*')
            .validate(move |input: &String| {
                if input != &pwd_clone {
                    Err("The passwords do not match!")
                } else {
                    Ok(())
                }
            })
            .interact()?;
        Ok(pwd)
    }

    fn get_object_label(&self, default: &str) -> Result<String, MgmError> {
        let label: String = cliclack::input("Enter object label:")
            .default_input(default)
            .placeholder("Default is empty. Max 40 characters")
            .validate(|input: &String| object_label_validator(input))
            .interact()?;
        Ok(label)
    }

    fn select_object_domains(&self, available_domains: &[ObjectDomain]) -> Result<Vec<ObjectDomain>, MgmError> {
        if available_domains.is_empty() {
            return Err(MgmError::InvalidInput("No available domains to select from".to_string()));
        }

        let domain_strings: Vec<String> = available_domains.iter().map(|d| format!("{}", d)).collect();

        let mut domains = cliclack::multiselect(
            format!("Select object domains. {}", MULTI_SELECT_PROMPT_HELP));
        domains = domains.item("all".to_string(), "All Domains", "Select all available domains");
        for d in domain_strings {
            domains = domains.item(d.clone(), d, "");
        }
        let domains = domains.interact()?;

        if domains.contains(&"all".to_string()) {
            Ok(available_domains.to_vec())
        } else {
            let ds = domains.join(",");
            Ok(ObjectDomain::vec_from_str(ds.as_str())?)
        }
    }

    fn select_object_capabilities(
        &self,
        available_capabilities: &[ObjectCapability],
        preselected_capabilities: &[ObjectCapability],
        prompt: Option<&str>) -> Result<Vec<ObjectCapability>, MgmError> {
        if available_capabilities.is_empty() {
            return Ok(vec![]);
        }

        let mut caps = available_capabilities.to_vec();
        caps.sort_by_key(|a| a.to_string());

        let p = prompt.unwrap_or("Select object capabilities");
        let mut capabilities = cliclack::multiselect(
            format!("{}. {}", p, MULTI_SELECT_PROMPT_HELP));

        capabilities = capabilities.initial_values(preselected_capabilities.to_vec());
        for c in caps {
            capabilities = capabilities.item(c, c.to_string(), "");
        }
        Ok(capabilities.interact()?)
    }

    fn select_command(&self, available_commands: &[MgmCommand]) -> Result<MgmCommand, MgmError> {
        let mut cmd_select = cliclack::select("");
        for cmd in available_commands {
            cmd_select = cmd_select.item(cmd.clone(), cmd.label, cmd.description);
        }
        Ok(cmd_select.interact()?)
    }

    fn select_algorithm(
        &self,
        available_algorithms: &[MgmAlgorithm],
        default_algorithm: Option<ObjectAlgorithm>,
        prompt: Option<&str>) -> Result<ObjectAlgorithm, MgmError> {
        if available_algorithms.is_empty() {
            return Err(MgmError::InvalidInput("No available algorithms to select from".to_string()));
        }

        let p = prompt.unwrap_or("Select algorithms:");

        let mut algorithms = cliclack::select(p);
        if let Some(default) = default_algorithm {
            algorithms = algorithms.initial_value(default);
        }
        for a in available_algorithms {
            algorithms = algorithms.item(a.algorithm(), a.label(), a.description());
        }
        Ok(algorithms.interact()?)
    }

    fn select_one_object(
        &self,
        available_objects: &[ObjectDescriptor],
        prompt: Option<&str>) -> Result<ObjectDescriptor, MgmError> {

        let p = prompt.unwrap_or("Select object:");
        let mut selector = cliclack::select(p);

        let mut objects = available_objects.to_vec();
        objects.sort_by_key(|a| a.label.clone());
        for obj in objects {
            let label = format!("0x{:04x} : {:40} : {}", obj.id, obj.label, obj.algorithm);
            selector = selector.item(obj, label, "");
        }
        Ok(selector.interact()?)
    }

    fn select_multiple_objects(
        &self,
        available_objects: &[ObjectDescriptor],
        preselect_all: bool,
        prompt: Option<&str>) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if available_objects.is_empty() {
            return Ok(vec![]);
        }

        let p = prompt.unwrap_or("Select objects");
        let mut selector = cliclack::multiselect(
            format!("{}. {}", p, MULTI_SELECT_PROMPT_HELP)
        ).required(false);
        if preselect_all {
            selector = selector.initial_values(available_objects.to_vec());
        }

        let mut objects = available_objects.to_vec();
        objects.sort_by_key(|a| a.label.clone());
        for obj in available_objects {
            let label = format!("0x{:04x} : {:40} : {}", obj.id, obj.label, obj.algorithm);
            selector = selector.item(obj.to_owned(), label, "");
        }
        Ok(selector.interact()?)
    }

    fn select_one_item<T: Clone+Eq>(
        &self,
        items: &[SelectionItem<T>],
        default_item: Option<&T>,
        prompt: Option<&str>) -> Result<T, MgmError> {
        if items.is_empty() {
            return Err(MgmError::InvalidInput("No available items to select from".to_string()));
        }

        let p = prompt.unwrap_or("");

        let mut selector = cliclack::select(p);
        if let Some(default) = default_item {
            selector = selector.initial_value(default.clone());
        }

        for item in items {
            selector = selector.item(item.value.to_owned(), item.label.to_owned(), item.hint.to_owned());
        }
        Ok(selector.interact()?)
    }

    fn select_multiple_items<T: Clone+Eq>(
        &self,
        available_items: &[SelectionItem<T>],
        preselected_items: &[T],
        required: bool,
        prompt: Option<&str>) -> Result<Vec<T>, MgmError> {
        if available_items.is_empty() {
            return Ok(vec![]);
        }

        let p = if let Some(_p) = prompt {
            format!("{}. {}", _p, MULTI_SELECT_PROMPT_HELP)
        } else {
            MULTI_SELECT_PROMPT_HELP.to_string()
        };

        let mut selector = cliclack::multiselect(p).required(required);
        selector = selector.initial_values(preselected_items.to_vec());

        for item in available_items {
            selector = selector.item(item.value.to_owned(), item.label.to_owned(), item.hint.to_owned());
        }
        Ok(selector.interact()?)
    }





    fn get_string_input(&self, prompt: &str, required: bool) -> Result<String, MgmError> {
        let input: String = cliclack::input(prompt)
            .required(required)
            .interact()?;
        Ok(input)
    }

    fn get_integer_input(&self, prompt: &str, required: bool, default: Option<usize>, placeholder: Option<&str>, min: usize, max: usize) -> Result<usize, MgmError> {
        let mut number = cliclack::input(prompt)
            .required(required)
            .validate(move |input: &String| integer_validator(input.as_str(), min, max));
        if let Some(d) = default {
            number = number.default_input(d.to_string().as_str());
        }
        if let Some(p) = placeholder {
            number = number.placeholder(p);
        }
        let input: String = number.interact()?;
        Ok(usize::from_str(&input).unwrap())
    }

    fn get_path_input(&self, prompt: &str, required: bool, default: Option<&str>, placeholder: Option<&str>) -> Result<String, MgmError> {
        let mut path = cliclack::input(prompt)
            .required(required)
            .validate(|input: &String| path_exists_validator(input.as_str()));
        if let Some(d) = default {
            path = path.default_input(d);
        }
        if let Some(p) = placeholder {
            path = path.placeholder(p);
        }
        let input: String = path.interact()?;
        Ok(input)
    }


    fn get_pem_filepath(&self, prompt: &str, required: bool, place_holder: Option<&str>) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            required,
            place_holder,
            Some(pem_file_validator))
    }

    fn get_certificate_filepath(&self, prompt: &str, required: bool, place_holder: Option<&str>) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            required,
            place_holder,
            Some(pem_certificate_file_validator))
    }

    fn get_public_eckey_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(pem_public_eckey_file_validator))
    }

    fn get_public_ecp256_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(pem_public_ecp256_file_validator))
    }

    fn get_private_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(pem_private_rsa_file_validator))
    }

    fn get_public_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(pem_public_rsa_file_validator))
    }


    fn get_aes_key_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            true,
            None,
            Some(crate::backend::validators::aes_key_validator))
    }

    fn get_aes_iv_hex(&self, prompt: &str, required: bool, default: Option<&str>) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            required,
            default,
            Some(crate::backend::validators::iv_validator))
    }

    fn get_aes_operation_input_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            true,
            None,
            Some(crate::backend::validators::aes_operation_input_validator))
    }




    fn get_split_aes_n_shares(&self, prompt: &str) -> Result<u8, MgmError> {
        let n = self.get_integer_input(
            prompt,
            true,
            None,
            Some("Must be greater than 0 and less than 256"),
            1,
            256)?;
        Ok(n as u8)
    }

    fn get_split_aes_m_threshold(&self, prompt: &str, n_shares: u8) -> Result<u8, MgmError> {
        let m = self.get_integer_input(
            prompt,
            true,
            None,
            Some(format!("Must be greater than 0 and less than {}", n_shares).as_str()),
            1,
            n_shares as usize)?;
        Ok(m as u8)
    }

    fn get_split_aes_share(&self, prompt: &str, share_length: Option<u8>) -> Result<String, MgmError> {
        let mut share = cliclack::input(prompt)
            .required(false)
            .validate(move |input: &String| aes_share_validator(input.as_str(), share_length));
        Ok(share.interact()?)
    }
















    fn display_objects_basic(&self, objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
        let specs:Vec<ObjectSpec> = objects.iter().map(|d| ObjectSpec::from(d.clone())).collect::<Vec<_>>();
        self.display_objects_spec(&specs)
    }

    fn display_objects_full(&self, objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
        if objects.is_empty() {
            cliclack::log::info("No objects to display.")?;
            return Ok(());
        }

        let mut _objects = objects.to_vec();
        _objects.sort_by_key(|a| a.label.clone());

        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["ID", "Type", "Label", "Algorithm", "Sequence", "Origin", "Domains", "Capabilities", "Delegated Capabilities"]);

        for object in _objects {
            let spec = ObjectSpec::from(object.clone());

            table.add_row(vec![
                spec.get_id_str(),
                spec.get_type_str(),
                spec.label.to_string(),
                spec.get_algorithm_str(),
                object.sequence.to_string(),
                format!("{:?}", object.origin),
                spec.get_domains_str(),
                spec.get_capabilities_str(),
                spec.get_delegated_capabilities_str()]);

        }
        cliclack::log::success(table.to_string().as_str())?;
        Ok(())
    }

    fn display_objects_spec(&self, objects: &[ObjectSpec]) -> Result<(), MgmError> {
        if objects.is_empty() {
            cliclack::log::info("No objects to display.")?;
            return Ok(());
        }

        let mut specs = objects.to_vec();
        specs.sort_by_key(|a| a.label.clone());

        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(vec!["ID", "Type", "Label", "Algorithm", "Domains", "Capabilities"]);

        for spec in specs {

            table.add_row(vec![
                spec.get_id_str(),
                spec.get_type_str(),
                spec.label.to_string(),
                spec.get_algorithm_str(),
                spec.get_domains_str(),
                spec.get_capabilities_str()]);

        }
        cliclack::log::success(table.to_string().as_str())?;
        Ok(())
    }





    fn display_success_message(&self, message: &str) -> Result<(), MgmError> {
        Ok(cliclack::log::success(message)?)
    }

    fn display_info_message(&self, message: &str) -> Result<(), MgmError> {
        Ok(cliclack::log::info(message)?)
    }

    fn display_note(&self, header: &str, note: &str) -> Result<(), MgmError> {
        Ok(cliclack::note(header, note)?)
    }

    fn display_warning(&self, message: &str) -> Result<(), MgmError> {
        Ok(cliclack::log::warning(message)?)
    }

    fn display_error_message(&self, message: &str) -> Result<(), MgmError> {
        Ok(cliclack::log::error(message)?)
    }

    fn get_confirmation(&self, prompt: &str) -> Result<bool, MgmError> {
        Ok(cliclack::confirm(prompt).interact()?)
    }

    fn get_warning_confirmation(&self, warning_message: &str) -> Result<bool, MgmError> {
        cliclack::log::warning(warning_message)?;
        Ok(cliclack::confirm("Continue?").interact()?)
    }

    fn get_note_confirmation(&self, prompt: &str,  message: &str) -> Result<bool, MgmError> {
        cliclack::note(prompt, message)?;
        Ok(cliclack::confirm("Continue?").interact()?)
    }


    fn clear_screen(&self) -> Result<(), MgmError> {
        Ok(cliclack::clear_screen()?)
    }

    fn start_spinner(&self, message: Option<&str>) -> Box<dyn SpinnerHandler> {
        let mut spinner = CliclackSpinner { spinner: cliclack::spinner() };
        spinner.start(message);
        Box::new(spinner)
    }

    fn stop_spinner(&self, mut spinner_handler: Box<dyn SpinnerHandler>, message: Option<&str>) {
        spinner_handler.stop(message);
    }
}

pub struct CliclackSpinner {
    spinner: cliclack::Spinner,
}
impl SpinnerHandler for CliclackSpinner {
    fn start(&mut self, message: Option<&str>) {
        let msg = message.unwrap_or("");
        self.spinner.start(msg);
    }

    fn stop(&mut self, success_message: Option<&str>) {
        let msg = success_message.unwrap_or("");
        self.spinner.stop(msg);
    }
}

// pub struct CliclackProgressBar {
//     progress: cliclack::progress_bar(100),
// }
// impl SpinnerHandler for CliclackSpinner {
//     fn start(&mut self, message: Option<&str>) {
//         let msg = message.unwrap_or("");
//         self.spinner.start(msg);
//     }
//
//     fn stop(&mut self, success_message: Option<&str>) {
//         let msg = success_message.unwrap_or("");
//         self.spinner.stop(msg);
//     }
// }

impl Cmdline {

    fn get_hex_input_ex<F>(
        &self,
        prompt: &str,
        required: bool,
        default: Option<&str>,
        validator: Option<F>,
    ) -> Result<Vec<u8>, MgmError>
        where
            F: Fn(&str) -> Result<(), MgmError> + 'static
    {
        let mut input_prompt = cliclack::input(prompt)
            .required(required)
            .default_input(default.unwrap_or(""));

        if let Some(v) = validator {
            input_prompt = input_prompt.validate(move |input: &String| v(input.as_str()));
        }
        let input: String = input_prompt.interact()?;
        Ok(hex::decode(input)?)
    }

    fn get_pem_filepath_ex<F>(
        &self,
        prompt: &str,
        required: bool,
        placeholder: Option<&str>,
        validator: Option<F>,
    ) -> Result<String, MgmError>
        where
            F: Fn(&str) -> Result<(), MgmError> + 'static
    {
        let mut file_path = cliclack::input(prompt)
            .required(required)
            .placeholder(placeholder.unwrap_or("Absolute path to PEM file"));

        if let Some(v) = validator {
            file_path = file_path.validate(move |input: &String| v(input.as_str()));
        }
        Ok(file_path.interact()?)
    }
}