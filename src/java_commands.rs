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

use std::fmt;
use std::fmt::{Display};
use std::sync::LazyLock;
use pem::Pem;

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;

use crate::backend::common::{get_new_object_note, contains_all};
use crate::backend::asym_utils::{EC_KEY_ALGORITHM, EC_KEY_CAPABILITIES, ED_KEY_CAPABILITIES, get_asym_object_from_der, java_import_key, RSA_KEY_ALGORITHM, RSA_KEY_CAPABILITIES};
use crate::backend::asym_utils::{java_get_keys, java_generate_key};
use crate::asym_commands::get_new_key_for_generation;
use crate::error::MgmError;
use crate::utils::{get_file_path, list_objects, delete_objects, select_delete_objects, fill_new_object_properties, get_pem_from_file};
use crate::MAIN_STRING;

static JAVA_STRING: LazyLock<String> = LazyLock::new(|| format!("{} > SunPKCS11 keys", MAIN_STRING));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum JavaCommand {
    #[default]
    List,
    Generate,
    Import,
    Delete,
    ReturnToMainMenu,
    Exit,
}

impl Display for JavaCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JavaCommand::List => write!(f, "List"),
            JavaCommand::Generate => write!(f, "Generate"),
            JavaCommand::Import => write!(f, "Import"),
            JavaCommand::Delete => write!(f, "Delete"),
            JavaCommand::ReturnToMainMenu => write!(f, "Return to main menu"),
            JavaCommand::Exit => write!(f, "Exit"),
        }
    }
}

pub fn exec_java_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        println!("\n{}", *JAVA_STRING);

        cliclack::note("",
            "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate \
        are store in the device with the same ObjectID".to_string())?;


        let cmd = get_command(authkey)?;
        let res = match cmd {
            JavaCommand::List => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::List);
                list(session)
            },
            JavaCommand::Generate => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Generate);
                generate(session, authkey)
            },
            JavaCommand::Import => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Import);
                import(session, authkey)
            },
            JavaCommand::Delete => {
                println!("\n{} > {}\n", *JAVA_STRING, JavaCommand::Delete);
                delete(session)
            },
            JavaCommand::ReturnToMainMenu => return Ok(()),
            JavaCommand::Exit => std::process::exit(0),
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}


fn get_command(authkey: &ObjectDescriptor) -> Result<JavaCommand, MgmError> {
    let auth_capabilities = &authkey.capabilities;

    let mut commands = cliclack::select("");
    commands = commands.item(JavaCommand::List, JavaCommand::List, "");

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::GenerateAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate]) {
        commands = commands.item(JavaCommand::Generate, JavaCommand::Generate, "");
    }

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate]) {
        commands = commands.item(JavaCommand::Import, JavaCommand::Import, "");
    }

    if contains_all(auth_capabilities.as_slice(),
                    &[ObjectCapability::DeleteAsymmetricKey, ObjectCapability::DeleteOpaque]) {
        commands = commands.item(JavaCommand::Delete, JavaCommand::Delete, "");
    }
    commands = commands.item(JavaCommand::ReturnToMainMenu, JavaCommand::ReturnToMainMenu, "");
    commands = commands.item(JavaCommand::Exit, JavaCommand::Exit, "");
    Ok(commands.interact()?)
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = java_get_keys(session)?;
    list_objects(session, &keys)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let keys = java_get_keys(session)?;

    let mut selected_keys = select_delete_objects(session, &keys)?;
    for key in selected_keys.clone() {
        let mut cert = ObjectDescriptor::new();
        cert.id = key.id;
        cert.object_type = ObjectType::Opaque;
        selected_keys.push(cert);
    }

    delete_objects(session, &selected_keys)
}

fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    let mut key = match get_new_key_for_generation(authkey)? {
        Some(k) => k,
        None => return Ok(()),
    };
    
    check_free_id(session, key.id)?;
    
    let mut spinner = cliclack::spinner();
    spinner.start("Generating SunPKCS11 compatible key...");
    key.id = java_generate_key(session, &key)?;
    spinner.stop("");
    cliclack::log::success(
        format!("Generated asymmetric key and stored attestation certificate with ID 0x{:04x} on the device", key.id))?;
    Ok(())
}

fn import(session: &Session, authkey: &ObjectDescriptor ) -> Result<(), MgmError> {

    let mut pems = get_pem_from_file(
        get_file_path("Enter absolute path to PEM file containing private key and/or X509Certificate:")?)?;
    if pems.len() > 2 {
        cliclack::log::info(format!("Found {} PEM objects in the file. Only the first private key and the first X509Certificate will be imported.", pems.len()))?;
    }

    let privkey;
    let mut privkey_descriptor = ObjectDescriptor::new();
    loop {
        if let Ok((_algo, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::AsymmetricKey) {
            privkey_descriptor.object_type = ObjectType::AsymmetricKey;
            privkey_descriptor.algorithm = _algo;
            privkey = _value;
            break;
        }
        cliclack::log::error("No private key found in PEM file. Please try again or press ESC to go back to menu")?;
        pems = get_pem_from_file(
            get_file_path("Enter absolute path to PEM file containing a private key:")?)?;
    }
    cliclack::log::success("Private key loaded from PEM file")?;

    let cert;
    loop {
        if let Ok((_algo, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::Opaque) {
            cert = _value;
            break;
        }
        cliclack::log::error("No X509Certificate found in PEM file. Please try again or press ESC to go back to menu")?;
        pems = get_pem_from_file(
            get_file_path("Enter absolute path to PEM file containing an X509Certificate:")?)?;
    }
    cliclack::log::success("X509Certificate loaded from PEM file")?;

    if RSA_KEY_ALGORITHM.contains(&privkey_descriptor.algorithm) {
        fill_new_object_properties(&mut privkey_descriptor, authkey, &RSA_KEY_CAPABILITIES, &[])?;
    } else if EC_KEY_ALGORITHM.contains(&privkey_descriptor.algorithm) {
        fill_new_object_properties(&mut privkey_descriptor, authkey, &EC_KEY_CAPABILITIES, &[])?;
    } else if privkey_descriptor.algorithm == ObjectAlgorithm::Ed25519 {
        fill_new_object_properties(&mut privkey_descriptor, authkey, &ED_KEY_CAPABILITIES, &[])?;
    }

    check_free_id(session, privkey_descriptor.id)?;

    cliclack::note("Importing SubPKCS11 compatible key with: ", get_new_object_note(&privkey_descriptor))?;
    if cliclack::confirm("Import key?").interact()? {
        privkey_descriptor.id = java_import_key(session, &mut privkey_descriptor, privkey.as_slice(), cert.as_slice())?;
        cliclack::log::success(format!("Imported private key and X509Certificate with ID 0x{:04x} into the device", privkey_descriptor.id))?;
    }

    Ok(())
}

fn get_first_object_from_pem(pems:Vec<Pem>, obj_type:ObjectType) -> Result<(ObjectAlgorithm, Vec<u8>), MgmError> {
    for pem in pems {
        let (_type, _algo, _value) = get_asym_object_from_der(pem.contents())?;
        if _type == obj_type {
            return Ok((_algo, _value));
        }
    }
    Err(MgmError::Error("No private key found in PEM file".to_string()))
}

fn check_free_id(session: &Session, id: u16) -> Result<(), MgmError> {
    if id != 0 &&
        (session.get_object_info(id, ObjectType::AsymmetricKey).is_ok() ||
            session.get_object_info(id, ObjectType::Opaque).is_ok()) {
        cliclack::log::error(format!("There already exists an asymmetric key and/or an opaque object with ID 0x{:04x}. Please try again with another ID or delete existing objects first", id))?;
        return Err(MgmError::Error("Object ID already in use".to_string()));
    }
    Ok(())
}