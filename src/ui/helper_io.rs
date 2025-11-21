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

use std::path::Path;
use std::fs;
use std::fs::File;
use pem::Pem;
use std::io::Write;
use crate::traits::ui_traits::YubihsmUi;
use crate::hsm_operations::error::MgmError;

pub fn get_string_or_bytes_from_file(ui: &impl YubihsmUi, string: String) -> Result<Vec<u8>, MgmError> {
    if string.is_empty() {
        return Ok(vec![])
    }

    match get_bytes_from_file(ui, &string) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(string.as_bytes().to_vec())
    }
}

pub fn get_hex_or_bytes_from_file(ui: &impl YubihsmUi, string: String) -> Result<Vec<u8>, MgmError> {
    if string.is_empty() {
        return Ok(vec![])
    }

    match get_bytes_from_file(ui, &string) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(hex::decode(string)?)
    }
}

pub fn get_bytes_from_file(ui: &impl YubihsmUi, filepath: &String) -> Result<Vec<u8>, MgmError> {
    if Path::new(filepath).exists() {
        ui.display_info_message(
            format!("Read bytes from file: {}", filepath).as_str())?;
        return Ok(fs::read(filepath)?)
    }
    Err(MgmError::InvalidInput("File does not exist".to_string()))
}

pub fn get_pem_from_file(file_path: &String) -> Result<Vec<Pem>, MgmError> {
    let content = fs::read_to_string(file_path)?;
    Ok(pem::parse_many(content)?)
}

pub fn write_bytes_to_file(ui: &impl YubihsmUi, content: &[u8], filename: &str, directory: Option<&str>) -> Result<(), MgmError> {
    let dir = if let Some(d) = directory { d.to_owned() } else { ".".to_owned() };
    let filepath = format!("{}/{}", dir, filename);

    let mut file = match File::options().create_new(true).write(true).open(&filepath) {
        Ok(f) => f,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                if ui.get_confirmation(format!("File {} already exist. Overwrite it?", &filepath).as_str())? {
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
    ui.display_success_message(format!("Wrote file {}", &filepath).as_str())?;
    Ok(())
}

