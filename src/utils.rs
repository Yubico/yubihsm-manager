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

extern crate yubihsmrs;

use std::{env, fs};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use cliclack::MultiSelect;
use pem::Pem;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain};
use crate::error::MgmError;
use comfy_table::{ContentArrangement, Table};
use crate::backend::types::{ObjectSpec, YhAlgorithm};
use crate::backend::common::{get_delegated_capabilities};

const MULTI_SELECT_PROMPT_HELP: &str = ". Press the space button to select and unselect item. Press 'Enter' when done.";



pub fn get_password(prompt: &str) -> Result<String, MgmError> {
    let pwd = cliclack::password(prompt)
        .mask('*')
        .interact()?;

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

pub fn get_id() -> Result<u16, MgmError> {
    let keyid_str: String = cliclack::input("Enter key ID:")
        .default_input("0")
        .placeholder("Default 0 for device generated ID")
        .validate(|input: &String| {
            if input.starts_with("0x") {
                if u16::from_str_radix(&input[2..], 16).is_err() {
                    Err("Key ID must be a 2 bytes long number")
                } else {
                    Ok(())
                }
            } else if u16::from_str(input).is_err() {
                Err("Key ID must be a 2-bytes long number")
            } else {
                Ok(())
            }
        })
        .interact()?;

    if keyid_str.starts_with("0x") {
        Ok(u16::from_str_radix(&keyid_str[2..], 16).unwrap())
    } else {
        Ok(u16::from_str(&keyid_str).unwrap())
    }
}

pub fn get_label() -> Result<String, MgmError> {
    Ok(cliclack::input("Enter key label: ")
        .default_input("")
        .placeholder("Default empty")
        .validate(|input: &String| {
            if input.len() > 40 {
                Err("Label must be maximum of 40 characters")
            } else {
                Ok(())
            }
        })
        .interact()?)
}

pub fn select_domains(selection: &Vec<ObjectDomain>) -> Result<Vec<ObjectDomain>, MgmError> {
    let mut domains: MultiSelect<u16> = cliclack::multiselect(
        format!("Select domain(s){}", MULTI_SELECT_PROMPT_HELP));
    domains = domains.initial_values(vec![u16::try_from(0xffff).unwrap()]);
    domains = domains.item(0xffff, "All Domains", "Select all domains");
    for d in selection {
        domains = domains.item((u16::from(*d).trailing_zeros() + 1) as u16, d, "");
    }
    let domains = domains.interact()?;

    if domains.contains(&u16::try_from(0xffff).unwrap()) {
        Ok(selection.clone())
    } else {
        let mut ds = Vec::new();
        for d in domains {
            ds.push(ObjectDomain::try_from(d)?)
        }
        Ok(ds)
    }
}

pub fn select_capabilities(
    prompt: &str,
    authkey: &ObjectDescriptor,
    capability_options: &[ObjectCapability],
    capabilities_preselected: &[ObjectCapability]) -> Result<Vec<ObjectCapability>, MgmError> {

    let authkey_delegated = get_delegated_capabilities(authkey);

    let mut caps_options = capability_options.to_vec();
    caps_options.retain(|c| authkey_delegated.contains(c));

    if caps_options.is_empty() {
        Ok(Vec::new())
    } else {
        caps_options.sort_by_key(|a| a.to_string());
        let mut selected_caps =
            cliclack::multiselect(format!("{}{}", prompt, MULTI_SELECT_PROMPT_HELP));
        selected_caps = selected_caps.required(false);
        if !capabilities_preselected.is_empty() {
            selected_caps = selected_caps.initial_values(capabilities_preselected.to_vec());
        }
        for c in caps_options {
            selected_caps = selected_caps
                .item(c, c.to_string(), format!("yubihsm-shell name: {:?}", c));
        }
        Ok(selected_caps.interact()?)
    }
}

pub fn select_algorithm(
    prompt:&str,
    algorithms:&[YhAlgorithm], default_algorithm: Option<ObjectAlgorithm>) -> Result<ObjectAlgorithm, MgmError> {

    let mut algo = cliclack::select(prompt);
    if let Some(item) = default_algorithm {
        algo = algo.initial_value(item);
    }
    for a in algorithms {
        algo = algo.item(a.algorithm, a.label, a.description);
    }
    let algo = algo.interact()?;
    Ok(algo)
}

pub fn fill_object_spec(
    authkey: &ObjectDescriptor,
    object_spec: &mut ObjectSpec,
    object_capabilities: &[ObjectCapability],
    preselected_capabilities: &[ObjectCapability]) -> Result<(), MgmError> {

    object_spec.id = get_id()?;
    object_spec.label = get_label()?;
    object_spec.domains = select_domains(&authkey.domains)?;
    object_spec.capabilities = select_capabilities(
        "Select object capabilities", authkey, object_capabilities, preselected_capabilities)?;
    Ok(())
}

fn get_descriptor_basic_display(desc: &ObjectDescriptor) -> String {
    format!("0x{:04x} : {:40} : {}",
            desc.id, desc.label, desc.algorithm)
}

pub fn select_one_object(
    prompt:&str,
    objects:&[ObjectDescriptor]) -> Result<ObjectDescriptor, MgmError> {
    if objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Err(MgmError::Error("No objects to select from".to_string()));
    }

    let mut options = objects.to_vec();
    options.sort_by(|a, b| a.label.cmp(&b.label));
    let mut selected_object = cliclack::select(prompt);
    for o in options {
        let description = get_descriptor_basic_display(&o);
        selected_object = selected_object.item(o, description, "");
    }
    Ok(selected_object.interact()?)
}


pub fn select_multiple_objects(
    prompt:&str,
    objects:&[ObjectDescriptor],
    default_select_all:bool) -> Result<Vec<ObjectDescriptor>, MgmError> {

    if objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Ok(Vec::new());
    }

    let mut options = objects.to_vec();
    options.sort_by(|a, b| a.label.cmp(&b.label));
    let mut selected = cliclack::multiselect(format!("{}{}", prompt, MULTI_SELECT_PROMPT_HELP));
    selected = selected.required(false);
    if default_select_all {
        selected = selected.initial_values(options.clone());
    }

    for o in options {
        let description = get_descriptor_basic_display(&o);
        selected = selected.item(o,description, "");
    }

    Ok(selected.interact()?)
}

pub fn select_delete_objects(objects: &[ObjectDescriptor]) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let objects = select_multiple_objects(
        "Select key(s) to delete", objects,false)?;

    if !objects.is_empty() {
        cliclack::log::warning("Selected object(s) will be deleted and cannot be recovered")?;
        if cliclack::confirm("Delete objects?").interact()? {
            return Ok(objects);
        }
    }
    Ok(Vec::new())
}

pub fn print_failed_delete(failed: &[(ObjectDescriptor, MgmError)]) -> Result<(), MgmError> {
    if failed.is_empty() {
        cliclack::log::success("Selected objects deleted successfully")?;
    } else {
        let fail = failed
            .iter()
            .map(|(d, e)| format!("0x{:04x}:{}:{}\n", d.id, d.object_type, e))
            .collect::<Vec<_>>()
            .join(", ");

        cliclack::log::error(format!("Failed to delete {} objects: \n{}\n", failed.len(), fail))?;
    }
    Ok(())
}

pub fn get_directory(prompt: &str) -> Result<String, MgmError> {
    let dir: String = cliclack::input(prompt)
        .placeholder("Default is current directory")
        .default_input(".")
        .validate(|input: &String| {
            if !Path::new(input).exists() {
                Err("No such directory. Please enter an existing path.")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(dir)
}

pub fn get_file_path(prompt:&str) -> Result<String, MgmError> {
    let file_path: String = cliclack::input(prompt)
        .required(true)
        .validate(|input: &String| {
            if !Path::new(input).exists() {
                Err("File does not exist")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(file_path)
}

pub fn read_string_from_file(prompt:&str) -> Result<String, MgmError> {
    let path = get_file_path(prompt)?;
    Ok(fs::read_to_string(path)?)
}

pub fn read_input_bytes(prompt: &str, expected_hex: bool) -> Result<Vec<u8>, MgmError> {
    let user_input: String = cliclack::input(prompt).interact()?;
    if user_input.is_empty() {
        return Err(MgmError::InvalidInput("No input to read".to_string()))
    }
    if Path::new(&user_input).exists() {
        cliclack::log::info(format!("Read input from binary file: {}", user_input))?;
        return Ok(fs::read(user_input)?)
    }
    if expected_hex {
        Ok(hex::decode(user_input)?)
    } else {
        Ok(user_input.as_bytes().to_vec())
    }
}

pub fn read_input_string(prompt: &str) -> Result<String, MgmError> {
    let user_input: String = cliclack::input(prompt).interact()?;
    if user_input.is_empty() {
        return Err(MgmError::InvalidInput("No input to read".to_string()))
    }
    if Path::new(&user_input).exists() {
        cliclack::log::info(format!("Read input from file: {}", user_input))?;
        return Ok(fs::read_to_string(user_input)?)
    }
    Ok(user_input)
}


pub fn read_bytes_from_file(prompt:&str) -> Result<Vec<u8>, MgmError> {
    let file_path = get_file_path(prompt)?;
    match fs::read(file_path) {
        Ok(content) => Ok(content),
        Err(err) => {
            cliclack::log::error("Failed to read file to bytes")?;
            if cliclack::confirm("Try again?").interact()? {
                read_bytes_from_file(prompt)
            } else {
                Err(MgmError::StdIoError(err))
            }
        }
    }
}

pub fn read_pem_from_file(file_path:String) -> Result<Pem, MgmError> {
    let content = fs::read_to_string(file_path)?;
    match pem::parse(content) {
        Ok(pem) => Ok(pem),
        Err(err) => {
            cliclack::log::error("Failed to parse file content as PEM")?;
            if cliclack::confirm("Try again?").interact()? {
                read_pem_from_file(get_file_path("")?)
            } else {
                Err(MgmError::PemError(err))
            }
        }
    }
}

pub fn read_pems_from_file(file_path:String) -> Result<Vec<Pem>, MgmError> {
    loop {
        let content = fs::read_to_string(file_path.clone())?;
        match pem::parse_many(content) {
            Ok(pem) => return Ok(pem),
            Err(err) => {
                cliclack::log::error(
                    format!("Failed to parse file content as PEM. {}\n\nPlease try again or press ESC to return to menu", err))?;
            }
        }
    }
}

pub fn read_aes_key_hex(prompt:&str) -> Result<Vec<u8>, MgmError> {
    let key_hex: String = cliclack::input(prompt)
        .validate(|input: &String| {
            let key_bytes = hex::decode(input);
            match key_bytes {
                Ok(k) => {
                    match k.len() {
                        16 | 24 | 32 => Ok(()),
                        _ => Err("AES key must be 16, 24 or 32 bytes long")
                    }
                },
                Err(_) => Err("Invalid hex string")
            }
        })
        .interact()?;
    Ok(hex::decode(key_hex)?)
}

pub fn write_bytes_to_file(content: &[u8], directory: &str, filename:&str) -> Result<(), MgmError> {
    let dir = if directory.is_empty() {
        env::current_dir()?.to_str().unwrap_or_default().to_owned()
    } else {
        directory.to_owned()
    };
    let filepath = format!("{}/{}", dir, filename);

    let mut file = match File::options().create_new(true).write(true).open(&filepath) {
        Ok(f) => f,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                if cliclack::confirm(format!("File {} already exist. Overwrite it?", &filepath)).interact()? {
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
    cliclack::log::success(format!("Wrote file {}", &filepath))?;
    Ok(())
}

pub fn print_object_properties(objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
    if objects.is_empty() {
        cliclack::log::info("No objects to display")?;
        return Ok(());
    }

    let object = select_one_object("", objects)?;

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["ID", "Type", "Label", "Algorithm", "Sequence", "Origin", "Domains", "Capabilities", "Delegated Capabilities"]);

    let id = format!("0x{:04x}", object.id);
    let origin = format!("{:?}", object.origin);

    let mut domains = String::new().to_owned();
    object.domains.iter().for_each(
        |domain| domains.push_str(format!("{:160},", domain).as_str()));
    domains.pop();

    let mut capabilities = String::new().to_owned();
    object.capabilities.iter().for_each(|cap| capabilities.push_str(format!("{:?},", cap).as_str()));
    capabilities.pop();

    let delegated_capabilities = {
        let mut delegated = String::new().to_owned();
        let caps = get_delegated_capabilities(&object);
        caps.iter().for_each(|cap| delegated.push_str(format!("{:?},", cap).as_str()));
        if !delegated.is_empty() {
            delegated.pop();
        }
        delegated
    };

    table.add_row(vec![
        id,
        object.object_type.to_string(),
        object.label.to_string(),
        object.algorithm.to_string(),
        object.sequence.to_string(),
        origin,
        domains,
        capabilities,
        delegated_capabilities]);

    println!("{table}");

    Ok(())
}

pub fn list_objects(objects: &[ObjectDescriptor]) -> Result<(), MgmError> {
    let mut objects = objects.to_vec();
    objects.sort_by(|a, b| a.label.cmp(&b.label));

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["ID", "Type", "Label", "Algorithm", "Domains", "Capabilities"]);

    for d in objects {
        let id = format!("0x{:04x}", d.id);
        let mut domains = String::new().to_owned();
        d.domains.iter().for_each(
            |domain| domains.push_str(format!("{:160},", domain).as_str()));
        domains.pop();

        let mut capabilities = String::new().to_owned();
        d.capabilities.iter().for_each(|cap| capabilities.push_str(format!("{:?},", cap).as_str()));
        capabilities.pop();

        table.add_row(vec![id, d.object_type.to_string(), d.label.to_string(), d.algorithm.to_string(), domains, capabilities]);
    }
    println!("{table}");
    Ok(())
}