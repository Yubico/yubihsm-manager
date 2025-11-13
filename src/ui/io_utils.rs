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
use std::fs::File;
use std::io::Write;
use std::path::Path;
use pem::Pem;
use crate::backend::error::MgmError;

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