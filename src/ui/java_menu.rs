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
use crate::ui::cmd_utils::{print_failed_delete, print_menu_headers, select_delete_objects};
use crate::backend::types::YhCommand;
use crate::ui::cmd_utils::select_command;
use crate::backend::asym::AsymOps;
use crate::backend::object_ops::Importable;
use crate::backend::types::ImportObjectSpec;
use crate::ui::asym_menu::fill_asym_spec;
use crate::backend::object_ops::{Deletable, Generatable, Obtainable};
use crate::backend::asym::JavaOps;
use crate::backend::types::ObjectSpec;
use crate::ui::cmd_utils::list_objects;

use crate::backend::error::MgmError;
use crate::ui::io_utils::{get_file_path, read_pems_from_file};

static JAVA_HEADER: &str = "SunPKCS11 keys";

pub fn exec_java_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {

    loop {

        print_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER]);

        cliclack::note("",
            "SunPKCS11 compatible keys entails that an asymmetric key and its equivalent X509Certificate \
        are store in the device with the same ObjectID".to_string())?;


        let cmd = select_command(&JavaOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, JAVA_HEADER, cmd.label]);

        let res = match cmd.command {
            YhCommand::List => list(session),
            YhCommand::Generate => generate(session, authkey),
            YhCommand::Import => import(session, authkey),
            YhCommand::Delete => delete(session),
            YhCommand::ReturnToMainMenu => return Ok(()),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

fn list(session: &Session) -> Result<(), MgmError> {
    let keys = JavaOps.get_all_objects(session)?;
    list_objects(&keys)
}

fn delete(session: &Session) -> Result<(), MgmError> {
    let keys = JavaOps.get_all_objects(session)?;
    let delete_keys = select_delete_objects(&keys)?;
    let failed = JavaOps.delete_multiple(session, &delete_keys);
    print_failed_delete(&failed)
}

pub fn generate(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let mut new_key = ObjectSpec::empty();
    fill_asym_spec(authkey, &mut new_key)?;

    cliclack::note("Generating SunPKCS11 compatible key with:", new_key.to_string())?;
    if cliclack::confirm("Generate key?").interact()? {
        let mut spinner = cliclack::spinner();
        spinner.start("Generating SunPKCS11 compatible key...");
        new_key.id = JavaOps.generate(session, &new_key)?;
        spinner.stop("");
        cliclack::log::success(
            format!("Generated asymmetric key and stored attestation certificate with ID 0x{:04x} on the device", new_key.id))?;
    }
    Ok(())
}

pub fn import(session: &Session, authkey: &ObjectDescriptor ) -> Result<(), MgmError> {

    let mut pems = read_pems_from_file(
        get_file_path("Enter absolute path to PEM file containing private key and/or X509Certificate (Only the first object of its type will be imported):")?)?;

    let mut spec = ObjectSpec::empty();
    let mut import_spec = ImportObjectSpec::empty();
    loop {
        if let Ok((_algo, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::AsymmetricKey) {
            spec.object_type = ObjectType::AsymmetricKey;
            spec.algorithm = _algo;
            import_spec.data.push(_value);
            break;
        }
        cliclack::log::error("No private key found in PEM file. Please try again or press ESC to go back to menu")?;
        pems = read_pems_from_file(
            get_file_path("Enter absolute path to PEM file containing a private key:")?)?;
    }
    cliclack::log::success("Private key loaded from PEM file")?;

    if pems.len() == 1 {
        pems = read_pems_from_file(
            get_file_path("Enter absolute path to PEM file containing an X509Certificate:")?)?;
    }
    loop {
        if let Ok((_, _value)) = get_first_object_from_pem(pems.clone(), ObjectType::Opaque) {
            import_spec.data.push(_value);
            break;
        }
        cliclack::log::error("No X509Certificate found in PEM file. Please try again or press ESC to go back to menu")?;
        pems = read_pems_from_file(
            get_file_path("Enter absolute path to PEM file containing an X509Certificate:")?)?;
    }
    cliclack::log::success("X509Certificate loaded from PEM file")?;

    fill_asym_spec(authkey, &mut spec)?;
    import_spec.object = spec;

    cliclack::note("Importing SunPKCS11 compatible key with: ", import_spec.object.to_string())?;
    if cliclack::confirm("Import key?").interact()? {
        let id = JavaOps.import(session, &import_spec)?;
        cliclack::log::success(format!("Imported private key and X509Certificate with ID 0x{:04x} into the device", id))?;
    }

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