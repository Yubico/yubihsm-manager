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
        Err(_) => {
            ui.display_info_message(
                format!("Read input as string \"{}\"", string).as_str());
            Ok(string.as_bytes().to_vec())
        }
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
            format!("Read bytes from file: {}", filepath).as_str());
        return Ok(fs::read(filepath)?)
    }
    Err(MgmError::InvalidInput("File does not exist".to_string()))
}

pub fn get_pem_from_file(file_path: &String) -> Result<Vec<Pem>, MgmError> {
    let content = fs::read_to_string(file_path)?;
    Ok(pem::parse_many(content)?)
}

fn expand_path(path:&str, is_directory: bool) -> Result<String, MgmError> {
    let expanded = if shellexpand::full(path).is_ok() {
        shellexpand::full(path).unwrap().to_string()
    } else {
        path.to_string()
    };

    let mut full_path = Path::new(expanded.as_str());
    if !is_directory {
        full_path = full_path.parent().unwrap_or(Path::new("."));
    }
    if let Err(e) = fs::create_dir_all(full_path) {
        return Err(MgmError::InvalidInput(format!("Failed to create or access directory {}. {}", full_path.display(), e)))
    }

    Ok(expanded)
}

pub fn get_path(ui: &impl YubihsmUi, prompt: &str, is_directory:bool, default_filepath: &str) -> Result<String, MgmError> {
    let path;
    loop {
        let p = if is_directory {
            ui.get_string_input(
                prompt,
                false,
                Some("."),
                Some("Default is current directory"))?
        } else {
            ui.get_string_input(
                prompt,
                false,
                Some(default_filepath),
                Some(format!("Default is {}", default_filepath).as_str()))?
        };
        match expand_path(p.as_str(), is_directory) {
            Ok(expanded) => {
                path = expanded;
                break;
            },
            Err(err) => ui.display_error_message(
                format!("{}\nPlease try again or press Esc to return to menu.", err).as_str()),
        }
    }
    Ok(path)
}

pub fn write_bytes_to_file(
    ui: &impl YubihsmUi,
    content: &[u8],
    filepath: &str) -> Result<(), MgmError> {

    let mut file = match File::options().create_new(true).write(true).open(filepath) {
        Ok(f) => f,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                if ui.get_confirmation(format!("File {} already exist. Overwrite it?", filepath).as_str())? {
                    fs::remove_file(filepath)?;
                    File::options().create_new(true).write(true).open(filepath)?
                } else {
                    let filename = Path::new(filepath).file_name().unwrap().to_str().unwrap();
                    let filename = get_path(
                        ui,
                        "Enter new output file path:",
                        false,
                        format!("./{}", filename).as_str())?;
                    return write_bytes_to_file(ui, content, filename.as_str())
                }
            } else {
                return Err(MgmError::StdIoError(error))
            }
        }
    };
    file.write_all(content)?;
    ui.display_success_message(format!("Wrote file {}", filepath).as_str());
    Ok(())
}

