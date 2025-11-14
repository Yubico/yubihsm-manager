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
use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor};
use yubihsmrs::Session;
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::device::DeviceOps;
use crate::backend::error::MgmError;
use crate::backend::object_ops::Obtainable;
use crate::backend::sym::SymOps;
use crate::backend::types::YhCommand;
use crate::backend::wrap::{WrapKeyType, WrapOps, WrapOpSpec, WrapType};
use std::fs::File;
use std::io::Read;
use crate::ui::cmd_utils::{print_menu_headers, select_algorithm, select_command, select_one_object};
use crate::ui::io_utils::{get_directory, write_bytes_to_file};

static DEVICE_HEADER: &str = "YubiHSM Device Operations";

pub fn exec_main_command(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    loop {

        print_menu_headers(&[DEVICE_HEADER]);

        let cmd = select_command(&DeviceOps::get_authorized_commands(authkey))?;
        print_menu_headers(&[crate::MAIN_HEADER, cmd.label]);

        let res = match cmd.command {
            YhCommand::GetRandom => get_random(session),
            YhCommand::BackupDevice => backup(session, authkey),
            YhCommand::RestoreDevice => restore(session, authkey),
            YhCommand::Reset => reset(session),
            YhCommand::ReturnToMainMenu => return Ok(()),
            YhCommand::Exit => std::process::exit(0),
            _ => unreachable!()
        };

        if let Err(e) = res {
            cliclack::log::error(e)?
        }
    }
}

pub fn get_random(session: &Session) -> Result<(), MgmError> {
    let n: usize = cliclack::input("Enter number of bytes")
        .default_input("256")
        .required(false)
        .placeholder("Can be maximum of 2028 bytes for newer YubiHSMs or 2021 for older ones. Default is 256")
        .validate(|input: &String| {
            if usize::from_str(input).is_err() {
                Err("Input must be a number number")
            } else if usize::from_str(input).unwrap() > 2028 {
                Err("The number must be no greater than 2028 for newer YubiHSMs or 2021 for older ones")
            } else {
                Ok(())
            }
        })
        .interact()?;
    let bytes = DeviceOps::get_random(session, n)?;
    println!("{}", hex::encode(bytes));
    Ok(())
}


fn backup(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_wrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the wrapping key to use for exporting objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };

    let export_objects = WrapOps::get_exportable_objects(session, &wrapkey, WrapType::Object)?;
    if export_objects.iter().any(|x| x.algorithm == ObjectAlgorithm::Ed25519) {
        wrap_op.include_ed_seed = cliclack::confirm("Include Ed25519 seed in the wrapped export? (required for importing Ed25519 keys)").interact()?
    };

    if wrapkey_type == WrapKeyType::RsaPublic {
        wrap_op.aes_algorithm = Some(select_algorithm(
            "Select AES algorithm to use for wrapping",
            &SymOps::get_object_algorithms(), Some(ObjectAlgorithm::Aes256))?);
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for wrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    let dir: String = get_directory("Enter path to backup directory:")?;

    let wrapped_objects = WrapOps::export_wrapped(session, &wrap_op, &export_objects)?;

    for object in &wrapped_objects {
        if object.error.is_some() {
            cliclack::log::warning(format!("Failed to wrap {} with ID 0x{:04x}: {}. Skipping...", object.object_type, object.object_id, object.error.as_ref().unwrap()))?;
            continue;
        }
        let filename = format!("0x{:04x}-{}.yhw", object.object_id, object.object_type);
        write_bytes_to_file(openssl::base64::encode_block(&object.wrapped_data).as_bytes(), &dir, filename.as_str())?;
    }

    Ok(())
}

fn restore(session: &Session, authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    let wrapkeys = WrapOps::get_unwrapping_keys(session, authkey)?;
    let wrapkey = select_one_object(
        "Select the unwrapping key to use for importing objects:",
        &wrapkeys)?;
    let wrapkey_type = WrapOps::get_wrapkey_type(wrapkey.object_type, wrapkey.algorithm)?;

    let dir = get_directory("Enter backup directory:")?;
    let files: Vec<_> = match scan_dir::ScanDir::files()
        .read(dir.clone(), |iter| {
            iter.filter(|(_, name)| name.ends_with(".yhw"))
                .map(|(entry, _)| entry.path())
                .collect()
        }) {
        Ok(f) => f,
        Err(err) => {
            cliclack::log::error(err)?;
            return Err(MgmError::Error("Failed to read files".to_string()))
        }
    };

    if files.is_empty() {
        cliclack::log::info(format!("No backup files were found in {}", dir))?;
        return Ok(())
    }

    let mut wrap_op = WrapOpSpec {
        wrapkey_id: wrapkey.id,
        wrapkey_type,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
    };
    if wrapkey_type == WrapKeyType::Rsa {
        wrap_op.oaep_algorithm = Some(select_algorithm(
            "Select OAEP algorithm to use for unwrapping",
            &MgmAlgorithm::RSA_OAEP_ALGORITHMS, Some(ObjectAlgorithm::RsaOaepSha256))?);
    }

    for f in files {
        cliclack::log::info(format!("reading {}", &f.display()))?;
        let mut file = File::open(&f)?;

        let mut wrap = String::new();
        file.read_to_string(&mut wrap)?;

        let res = WrapOps::import_wrapped(session, &wrap_op, wrap, None);
        match res {
            Ok(handle) => {
                cliclack::log::success(format!("Successfully imported object {}, with ID 0x{:04x}", handle.object_type, handle.object_id))?;
            },
            Err(e) => {
                cliclack::log::error(format!("Failed to import wrapped object from file {}: {}. Skipping...", f.display(), e))?;
            }
        }
    }
    Ok(())
}

pub fn reset(session: &Session) -> Result<(), MgmError> {
    cliclack::log::warning("All data will be deleted from the device and cannot be recovered.")?;
    if cliclack::confirm("Continue?").interact()? {
        DeviceOps::reset_device(session)?;
        cliclack::log::success("Device has been reset to factory defaults.")?;
    }
    Ok(())
}
