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

use std::sync::atomic::{AtomicBool, Ordering};
use std::str::FromStr;
use tabled::{Table, builder::Builder, settings::{Width, Modify, Style, object::Columns}};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain};
use crate::traits::ui_traits::YubihsmUi;
use crate::traits::ui_traits::ProgressBarHandler;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::common;
use crate::hsm_operations::validators;
use crate::hsm_operations::types::{MgmCommand, SelectionItem, NewObjectSpec};
use crate::hsm_operations::algorithms::MgmAlgorithm;

macro_rules! return_or_exit {
    ( $e:expr) => {
        match $e {
            Ok(x) => x,
            Err(err) => {
                if CTRL_C_PRESSED.load(Ordering::SeqCst) {
                    let _ = cliclack::outro_cancel("Exiting YubiHSM Manager!");
                    std::process::exit(1);
                } else {
                    return Err(MgmError::from(err));
                }
            },
        }
    }
}

macro_rules! do_or_exit {
    ( $e:expr) => {
        match $e {
            Ok(_) => {},
            Err(_err) => std::process::exit(1),
        }
    }
}

static CTRL_C_PRESSED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct Cmdline;

static MULTI_SELECT_PROMPT_HELP: &str = "Press the space button to select and unselect item. Press 'Enter' when done.";

impl YubihsmUi for Cmdline {

    fn get_new_object_id(&self, default: u16) -> Result<u16, MgmError> {
        let mut id = cliclack::input("Enter object ID:")
            .default_input(default.to_string().as_str())
            .placeholder(format!("Default is {} for device generated ID", default).as_str())
            .validate(|input: &String| validators::object_id_validator(input));
        let id:String = return_or_exit!(id.interact());
        common::get_id_from_string(id.as_str())
    }

    fn get_object_id(&self) -> Result<u16, MgmError> {
        let mut id = cliclack::input("Enter object ID:")
            .placeholder("Object ID in range [0, 65535]")
            .validate(|input: &String| validators::object_id_validator(input));
        let id:String = return_or_exit!(id.interact());
        common::get_id_from_string(id.as_str())
    }

    fn get_password(&self, prompt: &str, confirm: bool) -> Result<String, MgmError> {
        let pwd = return_or_exit!(cliclack::password(prompt).mask('*').interact());
        if !confirm {
            return Ok(pwd);
        }

        let pwd_clone = pwd.clone();
        return_or_exit!(cliclack::password("Re-enter password")
            .mask('*')
            .validate(move |input: &String| {
                if input != &pwd_clone {
                    Err("The passwords do not match!")
                } else {
                    Ok(())
                }
            }).interact());
        Ok(pwd)
    }

    fn get_object_label(&self, default: &str) -> Result<String, MgmError> {
        let label: String = return_or_exit!(cliclack::input("Enter object label:")
            .default_input(default)
            .placeholder("Default is empty. Max 40 characters")
            .validate(|input: &String| validators::object_label_validator(input))
            .interact());
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
        let domains = return_or_exit!(domains.interact());

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
            do_or_exit!(cliclack::log::info(
                "No capabilities available to select from. Most likely because logged in user does not have sufficient delegated capabilities"));
            return Ok(vec![]);
        }

        let mut caps = available_capabilities.to_vec();
        caps.sort_by_key(|a| a.to_string());

        let p = prompt.unwrap_or("Select object capabilities");
        let mut capabilities = cliclack::multiselect(
            format!("{}. {}", p, MULTI_SELECT_PROMPT_HELP)).required(false);

        capabilities = capabilities.initial_values(preselected_capabilities.to_vec());
        for c in caps {
            capabilities = capabilities.item(c, c.to_string(), "");
        }
        let capabilities = return_or_exit!(capabilities.interact());
        Ok(capabilities)
    }

    fn select_command(&self, available_commands: &[MgmCommand]) -> Result<MgmCommand, MgmError> {
        let mut cmd_select = cliclack::select("");
        for cmd in available_commands {
            cmd_select = cmd_select.item(cmd.clone(), cmd.label, cmd.description);
        }
        let cmd_select = return_or_exit!(cmd_select.interact());

        Ok(cmd_select)
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
        let algorithms = return_or_exit!(algorithms.interact());
        Ok(algorithms)
    }

    fn select_one_object(
        &self,
        available_objects: &[ObjectDescriptor],
        prompt: Option<&str>) -> Result<ObjectDescriptor, MgmError> {

        if available_objects.is_empty() {
            return Err(MgmError::InvalidInput("No available objects to select from".to_string()));
        }

        let p = prompt.unwrap_or("Select object:");
        let mut selector = cliclack::select(p);

        let mut objects = available_objects.to_vec();
        objects.sort_by_key(|a| a.label.clone());
        for obj in objects {
            let label = format!("0x{:04x} : {:40} : {}", obj.id, obj.label, obj.algorithm);
            selector = selector.item(obj, label, "");
        }
        let selector = return_or_exit!(selector.interact());
        Ok(selector)
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
        let mut selected = cliclack::multiselect(
            format!("{}. {}", p, MULTI_SELECT_PROMPT_HELP)
        ).required(false);
        if preselect_all {
            selected = selected.initial_values(available_objects.to_vec());
        }

        let mut objects = available_objects.to_vec();
        objects.sort_by_key(|a| a.label.clone());
        for obj in available_objects {
            let label = format!("0x{:04x} : {:40} : {}", obj.id, obj.label, obj.algorithm);
            selected = selected.item(obj.to_owned(), label, "");
        }
        let selected = return_or_exit!(selected.interact());
        Ok(selected)
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

        let mut selected = cliclack::select(p);
        if let Some(default) = default_item {
            selected = selected.initial_value(default.clone());
        }

        for item in items {
            selected = selected.item(item.value.to_owned(), item.label.to_owned(), item.hint.to_owned());
        }
        let selected = return_or_exit!(selected.interact());
        Ok(selected)
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

        let mut selected = cliclack::multiselect(p).required(required);
        selected = selected.initial_values(preselected_items.to_vec());

        for item in available_items {
            selected = selected.item(item.value.to_owned(), item.label.to_owned(), item.hint.to_owned());
        }
        let selected = return_or_exit!(selected.interact());
        Ok(selected)
    }





    fn get_string_input(&self, prompt: &str, required: bool, default_value: Option<&str>, placeholder: Option<&str>) -> Result<String, MgmError> {
        let mut input = cliclack::input(prompt).required(required);
        if let Some(d) = default_value {
            input = input.default_input(d);
        }
        if let Some(p) = placeholder {
            input = input.placeholder(p);
        }
        let input = return_or_exit!(input.interact());
        Ok(input)
    }

    fn get_integer_input(&self, prompt: &str, required: bool, default: Option<usize>, placeholder: Option<&str>, min: usize, max: usize) -> Result<usize, MgmError> {
        let mut number = cliclack::input(prompt)
            .required(required)
            .validate(move |input: &String| validators::integer_validator(input.as_str(), min, max));
        if let Some(d) = default {
            number = number.default_input(d.to_string().as_str());
        }
        if let Some(p) = placeholder {
            number = number.placeholder(p);
        }
        let input: String = return_or_exit!(number.interact());
        Ok(usize::from_str(&input).unwrap())
    }

    fn get_path_input(&self, prompt: &str, required: bool, default: Option<&str>, placeholder: Option<&str>) -> Result<String, MgmError> {
        let mut path = cliclack::input(prompt)
            .required(required)
            .validate(|input: &String| validators::path_exists_validator(input.as_str()));
        if let Some(d) = default {
            path = path.default_input(d);
        }
        if let Some(p) = placeholder {
            path = path.placeholder(p);
        }
        let input: String = return_or_exit!(path.interact());
        Ok(input)
    }


    fn get_pem_filepath(&self, prompt: &str, required: bool, place_holder: Option<&str>) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            required,
            place_holder,
            Some(validators::pem_file_validator))
    }

    fn get_certificate_filepath(&self, prompt: &str, required: bool, placeholder: Option<&str>) -> Result<String, MgmError> {
        let mut file_path = cliclack::input(prompt)
            .required(required)
            .placeholder(placeholder.unwrap_or("Absolute path to PEM file"))
            .validate(move |input: &String| {
                let f = if shellexpand::full(input.as_str()).is_ok() {
                    shellexpand::full(input.as_str()).unwrap().to_string()
                } else {
                    input.to_string()
                };
                validators::pem_certificate_file_validator(f.as_str(), required)
            });
        let file_path:String = return_or_exit!(file_path.interact());
        if let Ok(expanded) = shellexpand::full(file_path.as_str()) {
            return Ok(expanded.to_string());
        }
        Ok(file_path)
    }

    fn get_asymmetric_import_filepath(&self, prompt: &str, placeholder: Option<&str>) -> Result<String, MgmError> {
        let mut file_path = cliclack::input(prompt)
            .placeholder(placeholder.unwrap_or("Absolute path to PEM file containing asymmetric private key or X509 certificate"))
            .validate(move |input: &String| {
                let f = if shellexpand::full(input.as_str()).is_ok() {
                    shellexpand::full(input.as_str()).unwrap().to_string()
                } else {
                    input.to_string()
                };

                if validators::pem_certificate_file_validator(f.as_str(), true).is_ok() ||
                   validators::pem_private_key_file_validator(f.as_str()).is_ok() {
                    Ok(())
                } else {
                    Err(MgmError::InvalidInput("File is not a valid PEM certificate or private key".to_string()))
                }
            });
        let file_path:String = return_or_exit!(file_path.interact());
        if let Ok(expanded) = shellexpand::full(file_path.as_str()) {
            return Ok(expanded.to_string());
        }
        Ok(file_path)
    }

    fn get_sunpkcs11_import_filepath(&self, prompt: &str, placeholder: Option<&str>) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            placeholder,
            Some(validators::pem_sunpkcs11_file_validator))
    }

    fn get_public_eckey_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(validators::pem_public_eckey_file_validator))
    }

    fn get_public_ecp256_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(validators::pem_public_ecp256_file_validator))
    }

    fn get_private_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(validators::pem_private_rsa_file_validator))
    }

    fn get_public_rsa_filepath(&self, prompt: &str) -> Result<String, MgmError> {
        self.get_pem_filepath_ex(
            prompt,
            true,
            None,
            Some(validators::pem_public_rsa_file_validator))
    }


    fn get_aes_key_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            true,
            None,
            Some("16, 24 or 32 bytes in HEX format"),
            Some(validators::aes_key_validator))
    }

    fn get_aes_iv_hex(&self, prompt: &str, required: bool, default: Option<&str>) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            required,
            default,
            Some("16 bytes in HEX format"),
            Some(validators::iv_validator))
    }

    fn get_aes_operation_input_hex(&self, prompt: &str) -> Result<Vec<u8>, MgmError> {
        self.get_hex_input_ex(
            prompt,
            true,
            None,
            None,
            Some(validators::aes_operation_input_validator))
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
            .validate(move |input: &String| validators::aes_share_validator(input.as_str(), share_length));
        let share = return_or_exit!(share.interact());
        Ok(share)
    }
















    fn display_objects_list(&self, objects: &[ObjectDescriptor]) {
        if objects.is_empty() {
            do_or_exit!(cliclack::log::info("No objects to display."));
            return
        }

        let mut specs:Vec<NewObjectSpec> = objects.iter().map(|d| NewObjectSpec::from(d.clone())).collect::<Vec<_>>();
        specs.sort_by_key(|a| a.label.clone());

        let mut builder = Builder::default();
        builder.push_record(vec!["ID", "Type", "Label", "Algorithm", "Domains", "Capabilities"]);

        for spec in specs {

            builder.push_record(vec![
                spec.get_id_str(),
                spec.get_type_str(),
                spec.label.to_string(),
                spec.get_algorithm_str(),
                spec.get_domains_str(),
                spec.get_capabilities_str()]);

        }
        let table = builder.build();
        let table = Self::get_resized_table(table, 6);
        do_or_exit!(cliclack::log::success(table.to_string().as_str()));
    }

    fn display_objects_properties(&self, objects: &[ObjectDescriptor]) {
        if objects.is_empty() {
            do_or_exit!(cliclack::log::info("No objects to display."));
            return
        }

        let mut _objects = objects.to_vec();
        _objects.sort_by_key(|a| a.label.clone());

        let mut builder = Builder::default();
        builder.push_record(vec!["ID", "Type", "Label", "Algorithm", "Sequence", "Origin", "Domains", "Capabilities", "Delegated Capabilities"]);

        for object in _objects {
            let spec = NewObjectSpec::from(object.clone());

            builder.push_record(vec![
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
        let table = builder.build();
        let table = Self::get_resized_table(table, 9);
        do_or_exit!(cliclack::log::success(table.to_string().as_str()));
    }





    fn display_success_message(&self, message: &str) {
        do_or_exit!(cliclack::log::success(message))
    }

    fn display_info_message(&self, message: &str) {
        do_or_exit!(cliclack::log::info(message))
    }

    fn display_note(&self, header: &str, note: &str) {
        do_or_exit!(cliclack::note(header, note))
    }

    fn display_warning(&self, message: &str) {
        do_or_exit!(cliclack::log::warning(message))
    }

    fn display_error_message(&self, message: &str) {
        do_or_exit!(cliclack::log::error(message))
    }

    fn get_confirmation(&self, prompt: &str) -> Result<bool, MgmError> {
        let b = return_or_exit!(cliclack::confirm(prompt).interact());
        Ok(b)
    }

    fn get_warning_confirmation(&self, warning_message: &str) -> Result<bool, MgmError> {
        do_or_exit!(cliclack::log::warning(warning_message));
        let b = return_or_exit!(cliclack::confirm("Continue?").interact());
        Ok(b)
    }

    fn get_note_confirmation(&self, prompt: &str,  message: &str) -> Result<bool, MgmError> {
        do_or_exit!(cliclack::note(prompt, message));
        let b = return_or_exit!(cliclack::confirm("Continue?").interact());
        Ok(b)
    }


    fn clear_screen(&self) {
        do_or_exit!(cliclack::clear_screen())
    }

    fn start_progress(&self, message: Option<&str>) -> Box<dyn ProgressBarHandler> {
        let mut pb = CliclackProgressBar { progress: cliclack::progress_bar(0) };
        pb.start(message);
        Box::new(pb)
    }

    fn stop_progress(&self, mut progress_handler: Box<dyn ProgressBarHandler>, message: Option<&str>) {
        progress_handler.stop(message);
    }
}

pub struct CliclackProgressBar {
    progress: cliclack::ProgressBar,
}
impl ProgressBarHandler for CliclackProgressBar {
    fn start(&mut self, message: Option<&str>) {
        let msg = message.unwrap_or("");
        self.progress.start(msg);
    }

    fn stop(&mut self, success_message: Option<&str>) {
        let msg = success_message.unwrap_or("");
        self.progress.stop(msg);
    }
}

impl Cmdline {
    pub fn new() -> Self {
        // This code handles CRTL-C. Otherwise CRTL-C would behave like ESC and just exist the current prompt
        ctrlc::set_handler(move || {
            // std::process::exit(0);
            CTRL_C_PRESSED.store(true, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
        Cmdline {}
    }


    fn get_hex_input_ex<F>(
        &self,
        prompt: &str,
        required: bool,
        default: Option<&str>,
        placeholder: Option<&str>,
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
        if let Some(p) = placeholder {
            input_prompt = input_prompt.placeholder(p);
        }
        let input: String = return_or_exit!(input_prompt.interact());
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
            file_path = file_path.validate(move |input: &String| {
                if let Ok(expanded) = shellexpand::full(input. as_str()) {
                    v(expanded.as_ref())
                } else {
                    v(input.as_str())
                }
            });
        }
        let file_path: String = return_or_exit!(file_path.interact());
        if let Ok(expanded) = shellexpand::full(file_path.as_str()) {
            return Ok(expanded.to_string());
        }
        Ok(file_path)
    }

    fn get_resized_table(mut table: Table, columns: usize) -> String {

        table.with(Style::modern());


        if let Ok((terminal_width, _)) = crossterm::terminal::size() {
            let table_width = (terminal_width as f32 * 0.9) as usize;
            table.with(Width::increase(table_width));

            table.with(Modify::new(Columns::new(0..))
                .with(Width::wrap(table_width/columns).keep_words()));

        }
        table.to_string()
    }
}