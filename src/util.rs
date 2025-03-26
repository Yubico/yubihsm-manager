extern crate yubihsmrs;

use std::fmt::{Display};
use std::{env, fmt, fs};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Write};
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use cliclack::MultiSelect;
use openssl::bn::BigNumContext;
use openssl::ec::PointConversionForm;
use openssl::nid::Nid;
use pem::Pem;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::{Session};
use error::MgmError;
use comfy_table::{Table,ContentArrangement};

const MULTI_SELECT_PROMPT_HELP: &str = ". Press the space button to select and unselect item. Press 'Enter' when done.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputOutputFormat {
    #[default]
    STDIN,
    BINARY,
    HEX,
    PEM,
    PASSWORD,
}

impl Display for InputOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InputOutputFormat::STDIN => write!(f, "Keybord input"),
            InputOutputFormat::BINARY => write!(f, "Binary file"),
            InputOutputFormat::HEX => write!(f, "Hex format"),
            InputOutputFormat::PEM => write!(f, "PEM format"),
            InputOutputFormat::PASSWORD => write!(f, "Password"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicDescriptor {
    pub id: u16,
    pub label:String,
    pub algorithm: ObjectAlgorithm,
}

impl Display for BasicDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:04x} : {:40} : {}",
             self.id, self.label, self.algorithm)
    }
}

impl From<ObjectDescriptor> for BasicDescriptor {
    fn from(object_desc: ObjectDescriptor) -> Self {
        BasicDescriptor {
            id: object_desc.id,
            label: object_desc.label,
            algorithm: object_desc.algorithm,
        }
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
    let mut domains: MultiSelect<u16> = cliclack::multiselect(
        "Select domain(s). Press the space button to select and unselect item. Press 'Enter' when done.");
    domains = domains.initial_values(vec![u16::try_from(0).unwrap()]);
    domains = domains.item(0, "All Domains", "Select all domains");
    for d in 1..16 {
        domains = domains.item(d, d, "");
    }
    let domains = domains.interact()?;

    if domains.contains(&u16::try_from(0).unwrap()) {
        Ok(ObjectDomain::from_primitive(0xffff))
    } else {
        let mut ds = Vec::new();
        for d in domains {
            ds.push(ObjectDomain::try_from(d)?)
        }
        Ok(ds)
    }
}

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

pub fn convert_handlers(session:&Session, handlers: &[ObjectHandle]) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let descriptors: Vec<ObjectDescriptor> = handlers
        .iter()
        .map(|k| session.get_object_info(k.object_id, k.object_type))
        .collect::<Result<_, _>>()?;
    Ok(descriptors)
}

pub fn select_one_object(
    prompt:&str,
    objects:Vec<ObjectDescriptor>) -> Result<ObjectDescriptor, MgmError> {
    if objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Err(MgmError::Error("No objects to select from".to_string()));
    }

    let mut selected_object = cliclack::select(prompt);
    for desc in objects {
        selected_object = selected_object.item(desc.clone(), BasicDescriptor::from(desc), "");
    }
    Ok(selected_object.interact()?)
}

pub fn select_multiple_objects(
    prompt:&str,
    objects:Vec<ObjectDescriptor>,
    default_select_all:bool) -> Result<Vec<ObjectDescriptor>, MgmError> {
    if objects.is_empty() {
        cliclack::log::info("No objects available")?;
        return Ok(Vec::new());
    }

    let mut selected = cliclack::multiselect(format!("{}{}", prompt, MULTI_SELECT_PROMPT_HELP));
    selected = selected.required(false);
    if default_select_all {
        selected = selected.initial_values(objects.clone());
    }

    for obj in objects {
        selected = selected.item(obj.clone(),BasicDescriptor::from(obj), "");
    }

    Ok(selected.interact()?)
}

pub fn delete_objects(session: &Session, handles: Vec<ObjectHandle>) -> Result<(), MgmError> {
    let objects = select_multiple_objects(
        "Select key(s) to delete", convert_handlers(session, &handles)?,false)?;

    if objects.is_empty() {
        cliclack::log::info("No keys were selected")?;
    } else {
        cliclack::log::warning("Selected object(s) will be deleted and cannot be recovered")?;
        if cliclack::confirm("Delete objects?").interact()? {
            for object in objects {
                session.delete_object(object.id, object.object_type)?;
                cliclack::log::success(format!("Deleted {} with id 0x{:04x}", object.object_type, object.id))?;
            }
        }
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
        .validate(|input: &String| {
            if input.is_empty() {
                Err("Value is required!")
            } else if !Path::new(input).exists() {
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


pub fn read_file_bytes(prompt:&str) -> Result<Vec<u8>, MgmError> {
    let file_path = get_file_path(prompt)?;
    match fs::read(file_path) {
        Ok(content) => Ok(content),
        Err(err) => {
            cliclack::log::error("Failed to read file to bytes")?;
            if cliclack::confirm("Try again?").interact()? {
                read_file_bytes(prompt)
            } else {
                Err(MgmError::StdIoError(err))
            }
        }
    }
}

pub fn read_pem_file(file_path:String) -> Result<Pem, MgmError> {
    let content = fs::read_to_string(file_path)?;
    match pem::parse(content) {
        Ok(pem) => Ok(pem),
        Err(err) => {
            cliclack::log::error("Failed to parse file content as PEM")?;
            if cliclack::confirm("Try again?").interact()? {
                read_pem_file(get_file_path("")?)
            } else {
                Err(MgmError::PemError(err))
            }
        }
    }
}

pub fn get_ec_pubkey_from_pem_string(pem_str:String) -> Result<(Vec<u8>, Nid), MgmError> {
    let pubkey = openssl::ec::EcKey::public_key_from_pem(pem_str.as_bytes())?;
    let mut ctx = BigNumContext::new()?;
    let ec_point_ref = pubkey.public_key();
    let ec_group_ref = pubkey.group();
    let key = ec_point_ref.to_bytes(ec_group_ref, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let nid = ec_group_ref.curve_name().ok_or(MgmError::Error(String::from("Failed to find EC curve name")))?;
    Ok((key, nid))
}

pub fn get_ec_privkey_from_pem_string(pem_str:String) -> Result<Vec<u8>, MgmError> {
    let privkey = openssl::ec::EcKey::private_key_from_pem(pem_str.as_bytes())?;
    let s = privkey.private_key();
    Ok(s.to_vec())
}

pub fn write_bytes_to_file(content: Vec<u8>, directory: &str, filename:&str) -> Result<(), MgmError> {
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
    file.write_all(content.deref())?;
    cliclack::log::success(format!("Wrote file {}", &filepath))?;
    Ok(())
}

pub fn print_object_properties(session: &Session, objects:Vec<ObjectHandle>) -> Result<(), MgmError> {
    if objects.is_empty() {
        cliclack::log::info("No objects to display")?;
        return Ok(());
    }

    let result = select_one_object("", convert_handlers(session, &objects)?)?;
    cliclack::log::success(result.to_string().replace('\t', "\n"))?;
    Ok(())
}

pub fn list_objects(session: &Session, objects: &[ObjectHandle]) -> Result<(), MgmError> {
    let mut descs = convert_handlers(session, objects)?;
    descs.sort_by(|a, b| a.id.cmp(&b.id));

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["ID", "Label", "Algorithm", "Domains", "Capabilities"]);
    for d in descs {
        let id = format!("0x{:04x}", d.id);
        let mut domains = String::new().to_owned();
        d.domains.iter().for_each(
            |domain| domains.push_str(format!("{:160},", domain).as_str()));
        domains.pop();

        let mut capabilities = String::new().to_owned();
        d.capabilities.iter().for_each(|cap| capabilities.push_str(format!("{:?},", cap).as_str()));
        capabilities.pop();

        table.add_row(vec![id, d.label.to_string(), d.algorithm.to_string(), domains, capabilities]);
    }
    println!("{table}");
    Ok(())
}

pub fn get_op_key(
    session:&Session,
    authkey: &ObjectDescriptor,
    op_capabilities: &[ObjectCapability],
    key_type: ObjectType,
    key_algos: &[ObjectAlgorithm]) -> Result<ObjectDescriptor, MgmError> {

    let mut key_capabilities = op_capabilities.to_vec();
    key_capabilities.retain(|c| authkey.capabilities.contains(c));
    if key_capabilities.is_empty() {
        return Err(MgmError::Error("There are no keys available for operation".to_string()))
    }

    let keys = session.list_objects_with_filter(
        0,
        key_type,
        "",
        ObjectAlgorithm::ANY,
        &key_capabilities)?;
    if keys.is_empty() {
        return Err(MgmError::Error("There are no keys available for operation".to_string()))
    }
    let mut keys = convert_handlers(session, &keys)?;

    if !key_algos.is_empty() {
        keys.retain(|desc| key_algos.contains(&desc.algorithm));
    }
    if keys.is_empty() {
        return Err(MgmError::Error("There are no keys available for operation".to_string()))
    }

    select_one_object("Select operation key", keys)
}

pub fn get_delegated_capabilities(authkey: &ObjectDescriptor) -> Vec<ObjectCapability>  {
    match &authkey.delegated_capabilities {
        Some(caps) => caps.clone(),
        None => Vec::new()
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

pub fn get_new_object_basics(
    authkey: &ObjectDescriptor,
    object_type: ObjectType,
    capability_options: &[ObjectCapability],
    capabilities_preselected: &[ObjectCapability]) -> Result<ObjectDescriptor, MgmError> {
    let mut desc = ObjectDescriptor::new();
    desc.object_type = object_type;
    desc.id = get_id()?;
    desc.label = get_label()?;
    desc.domains = select_domains(&authkey.domains)?;
    desc.capabilities = select_capabilities(
        "Select object capabilities", authkey, capability_options, capabilities_preselected)?;
    Ok(desc)
}

pub fn contains_all(set: &[ObjectCapability], subset: &[ObjectCapability]) -> bool {
    for c in subset {
        if !set.contains(c) {
            return false
        }
    }
    return true
}