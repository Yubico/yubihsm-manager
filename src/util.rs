extern crate yubihsmrs;

use std::fmt::Display;
use std::{fmt, fs};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Write};
use std::ops::Deref;
use std::str::FromStr;
use cliclack::MultiSelect;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::{Session};
use error::MgmError;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicDescriptor {
    pub object_id: u16,
    pub object_label:String,
    pub object_algorithm: ObjectAlgorithm,
}

impl Display for BasicDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:04x} : {:40} : {}", self.object_id, self.object_label, self.object_algorithm)
    }
}

impl From<ObjectDescriptor> for BasicDescriptor {
    fn from(object_desc: ObjectDescriptor) -> Self {
        BasicDescriptor {object_id: object_desc.id, object_label: object_desc.label, object_algorithm: object_desc.algorithm}
    }
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

pub fn get_domains() -> Result<Vec<ObjectDomain>, MgmError> {
    let mut domains: MultiSelect<ObjectDomain> = cliclack::multiselect(
        "Select domain(s). Press the space button to select and unselect item. Press 'Enter' when done.");
    for d in 1..16 {
        domains = domains.item(ObjectDomain::try_from(d).unwrap(), d, "");
    }
    Ok(domains.interact()?)
}

pub fn select_one_object(session: &Session, all_objects:Vec<ObjectHandle>, prompt:&str) -> Result<ObjectDescriptor, MgmError> {
    if all_objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Err(MgmError::Error("No objects to select from".to_string()));
    }

    let mut selected_object = cliclack::select(prompt);
    for object in all_objects {
        let desc = session.get_object_info(object.object_id, object.object_type)?;
        selected_object = selected_object.item(desc.clone(), BasicDescriptor::from(desc), "");
    }
    Ok(selected_object.interact()?)
}

pub fn select_multiple_objects(
    session: &Session,
    all_objects:Vec<ObjectHandle>,
    prompt:&str,
    default_select_all:bool) -> Result<Vec<ObjectDescriptor>, MgmError> {
    if all_objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Ok(Vec::new());
    }

    let mut all_descriptors: Vec<ObjectDescriptor> = Vec::new();
    for object in all_objects {
        all_descriptors.push(session.get_object_info(object.object_id, object.object_type)?);
    }

    let mut selected_objects = cliclack::multiselect(
        String::from(prompt) + ". Press the space button to select and unselect item. Press 'Enter' when done.");
    selected_objects = selected_objects.required(false);
    if default_select_all {
        selected_objects = selected_objects.initial_values(all_descriptors.clone());
    }

    for desc in all_descriptors {
        selected_objects = selected_objects.item(desc.clone(),BasicDescriptor::from(desc), "");
    }

    Ok(selected_objects.interact()?)
}

pub fn delete_objects(session: &Session, object_handles: Vec<ObjectHandle>) -> Result<(), MgmError> {
    let objects = select_multiple_objects(
        session, object_handles, "Select key(s) to delete", false);
    if let Ok(..) = objects {
        let objects = objects?;
        if !objects.is_empty() {
            cliclack::log::warning("Selected object(s) will be deleted and cannot be recovered")?;
            if cliclack::confirm("Delete objects?").interact()? {
                for object in objects {
                    session.delete_object(object.id, object.object_type)?;
                    cliclack::log::success(format!("Deleted {} with id 0x{:04x}", object.object_type, object.id))?;
                }
            }
        }
    }
    Ok(())
}

pub fn read_file(prompt:&str) -> Result<String, MgmError> {
    let file_path: String = cliclack::input(prompt)
        .validate(|input: &String| {
            if input.is_empty() {
                Err("Value is required!")
            } else if fs::read_to_string(input).is_err() {
                Err("File unreadable")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(fs::read_to_string(file_path)?)
}

pub fn read_file_bytes(prompt:&str) -> Result<Vec<u8>, MgmError> {
    let file_path: String = cliclack::input(prompt)
        .validate(|input: &String| {
            if input.is_empty() {
                Err("Value is required!")
            } else if fs::read(input).is_err() {
                Err("File unreadable")
            } else {
                Ok(())
            }
        })
        .interact()?;
    Ok(fs::read(file_path)?)
}

pub fn write_file(content: Vec<u8>, filename:&String) -> Result<(), MgmError> {
    let mut file = match File::options().create_new(true).write(true).open(filename) {
        Ok(f) => f,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                if cliclack::confirm(format!("File {} already exist. Overwrite it?", filename)).interact()? {
                    fs::remove_file(filename)?;
                    File::options().create_new(true).write(true).open(filename)?
                } else {
                    return Ok(())
                }
            } else {
                return Err(MgmError::StdIoError(error))
            }
        }
    };
    match file.write_all(content.deref()) {
        Ok(_) => cliclack::log::success(format!("Wrote file {}", filename))?,
        Err(err) => return Err(MgmError::StdIoError(err)),
    }
    Ok(())
}

pub fn print_object_properties(session: &Session, all_objects:Vec<ObjectHandle>) -> Result<(), MgmError> {
    if all_objects.is_empty() {
        cliclack::log::info("No objects to display")?;
        return Ok(());
    }

    let result = select_one_object(session, all_objects, "");
    if result.is_ok() {
        cliclack::log::success(result.unwrap().to_string().replacen('\t', "\n", 10))?;
    }
    Ok(())
}

pub fn get_object_properties_str(
    algo: &ObjectAlgorithm,
    label: &String,
    id: u16,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability]) -> String {

    let mut str = String::new();
    str.push_str(format!("    Key algorithm: {}\n", algo).as_str());
    str.push_str(format!("    Label: {}\n", label).as_str());
    if id == 0 {
        str.push_str("    Key ID: Device generated\n");
    } else {
        str.push_str(format!("    Key ID: 0x{:04x}\n", id).as_str());
    }
    str.push_str("    Domains: ");
    domains.iter().for_each(|domain| str.push_str(format!("{}, ", domain).as_str()));
    str.push('\n');
    str.push_str("    Capabilities: ");
    capabilities.iter().for_each(|cap| str.push_str(format!("{:?}, ", cap).as_str()));
    str.push('\n');
    str
}

pub fn get_object_properties_str_with_delegated(
    algo: &ObjectAlgorithm,
    label: &String,
    id: u16,
    domains: &[ObjectDomain],
    capabilities: &[ObjectCapability],
    delegated_capabilities: &[ObjectCapability]) -> String {

    let mut str = get_object_properties_str(algo, label, id, domains, capabilities);
    str.push_str("    Delegated Capabilities: ");
    delegated_capabilities.iter().for_each(|cap| str.push_str(format!("{:?}, ", cap).as_str()));
    str.push('\n');
    str
}

pub fn list_objects(session: &Session, objects: &Vec<ObjectHandle>) -> Result<(), MgmError> {
    cliclack::log::remark(format!("Found {} objects", objects.len()))?;
    for object in objects {
        println!("  {}", BasicDescriptor::from(session.get_object_info(object.object_id, object.object_type)?));
    }
    Ok(())
}

pub fn get_intesected_capabilities(vec1: &Vec<ObjectCapability>, vec2: &Vec<ObjectCapability>) -> Vec<ObjectCapability> {
    let caps1: HashSet<ObjectCapability> = vec1.clone().into_iter().collect();
    let caps2: HashSet<ObjectCapability> = vec2.clone().into_iter().collect();
    caps1.intersection(&caps2).copied().collect::<Vec<ObjectCapability>>()
}

pub fn select_object_capabilities(
    prompt: &str,
    default_select_all: bool,
    calculate_intersection: bool,
    type_capabilities:&Vec<ObjectCapability>,
    permissible_capabilities:&Vec<ObjectCapability>) -> Result<Vec<ObjectCapability>, MgmError> {

    let selectable_capabilities: Vec<ObjectCapability> =
        if calculate_intersection {
            get_intesected_capabilities(type_capabilities, permissible_capabilities)
        } else {
            type_capabilities.clone()
        };

    let mut capabilities = cliclack::multiselect(
        prompt.to_string() + ". Press the space button to select and unselect item. Press 'Enter' when done.");

    if default_select_all {
        capabilities = capabilities.initial_values(selectable_capabilities.clone());
    }

    capabilities = capabilities.required(false);
    for c in selectable_capabilities {
        capabilities = capabilities.item(c, c.to_string(), "");
    }
    Ok(capabilities.interact()?)
}

pub fn get_permissible_capabilities(session: &Session, current_authkey: u16) -> Result<Vec<ObjectCapability>, MgmError> {
    let delegated_capabilities: Option<Vec<ObjectCapability>> =
        session.get_object_info(current_authkey, ObjectType::AuthenticationKey)?
            .delegated_capabilities;
    let delegated_capabilities = match delegated_capabilities {
        Some(caps) => caps,
        None => {
            cliclack::log::info("Current authkey has no delegated capabilities".to_string())?;
            Vec::new()
        },
    };
    Ok(delegated_capabilities)
}