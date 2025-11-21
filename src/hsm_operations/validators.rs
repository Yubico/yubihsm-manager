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

use std::sync::LazyLock;
use regex::Regex;
use pem::Pem;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::asym::AsymmetricOperations;

static SHARE_RE_256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{70}$").unwrap());
static SHARE_RE_192: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{59}$").unwrap());
static SHARE_RE_128: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-zA-Z0-9+/]{48}$").unwrap());

pub fn object_id_validator(input: &str) -> Result<(), MgmError> {
    let id = if let Some(hex) = input.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        input.parse()
    };
    match id {
        Ok(id) if (0..=0xffff).contains(&id) => Ok(()),
        _ => Err(MgmError::InvalidInput("ID must be a number in [0, 65535]".to_string())),
    }
}

pub fn object_label_validator(input: &str) -> Result<(), MgmError> {
    if input.len() > 40 {
        Err(MgmError::InvalidInput("Label must be at most 40 characters long".to_string()))
    } else {
        Ok(())
    }
}

pub fn path_exists_validator(input: &str) -> Result<(), MgmError> {
    if std::path::Path::new(input).exists() {
        Ok(())
    } else {
        Err(MgmError::InvalidInput("No such file or directory".to_string()))
    }
}

pub fn integer_validator(input: &str, min: usize, max: usize) -> Result<(), MgmError> {
    match input.parse::<usize>() {
        Ok(value) if (min..=max).contains(&value) => Ok(()),
        _ => Err(MgmError::InvalidInput(format!("Input must be an integer in [{}, {}]", min, max))),
    }
}

pub fn hex_validator(input: &str) -> Result<(), MgmError> {
    match hex::decode(input) {
        Ok(_) => Ok(()),
        _ => Err(MgmError::InvalidInput("Input not in HEX format".to_string())),
    }
}

pub fn aes_key_validator(input: &str) -> Result<(), MgmError> {
    let key_bytes = hex::decode(input)?;
    match key_bytes.len() {
        16 | 24 | 32 => Ok(()),
        _ => Err(MgmError::InvalidInput("AES key must be 16, 24, or 32 bytes long".to_string())),
    }
}

pub fn aes_operation_input_validator(input: &str) -> Result<(), MgmError> {
    let data_bytes = hex::decode(input)?;
    match data_bytes.len() % 16 {
        0 => Ok(()),
        _ => Err(MgmError::InvalidInput("Input data must be a multiple of 16 bytes long".to_string())),
    }
}

pub fn iv_validator(input: &str) -> Result<(), MgmError> {
    let iv_bytes = hex::decode(input)?;
    match iv_bytes.len() {
        16 => Ok(()),
        _ => Err(MgmError::InvalidInput("IV must be 16 bytes long".to_string())),
    }
}

fn get_validated_pem_content(input: &str) -> Result<Pem, MgmError> {
    if !std::path::Path::new(input).exists() {
        return Err(MgmError::InvalidInput("File does not exist".to_string()));
    }
    let content = std::fs::read_to_string(input)?;
    Ok(pem::parse(content)?)
}

pub fn pem_file_validator(input: &str) -> Result<(), MgmError> {
    match get_validated_pem_content(input) {
        Ok(_) => Ok(()),
        Err(_) => Err(MgmError::InvalidInput("File is not a valid PEM".to_string())),
    }
}

pub fn pem_certificate_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _algo != ObjectAlgorithm::OpaqueX509Certificate {
        return Err(MgmError::InvalidInput("PEM content is not an X509Certificate".to_string()));
    }
    Ok(())
}

pub fn pem_public_eckey_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || !AsymmetricOperations::is_ec_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("PEM is not a public EC key".to_string()));
    }
    Ok(())
}

pub fn pem_public_ecp256_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || _algo != ObjectAlgorithm::EcP256 {
        return Err(MgmError::InvalidInput("PEM is not a public ECP256 key".to_string()));
    }
    Ok(())
}

pub fn pem_private_ecp256_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::AsymmetricKey || _algo != ObjectAlgorithm::EcP256 {
        return Err(MgmError::InvalidInput("PEM is not a private ECP256 key".to_string()));
    }
    Ok(())
}

pub fn pem_private_rsa_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::AsymmetricKey || AsymmetricOperations::is_rsa_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("PEM is not a private RSA key".to_string()));
    }
    Ok(())
}

pub fn pem_public_rsa_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?;
    let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || AsymmetricOperations::is_rsa_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("PEM is not a public RSA key".to_string()));
    }
    Ok(())
}

pub fn aes_share_validator(input: &str, share_length: Option<u8>) -> Result<(), MgmError> {
    let is_valid = match share_length {
        Some(74) => SHARE_RE_256.is_match(input),
        Some(63) => SHARE_RE_192.is_match(input),
        Some(52) => SHARE_RE_128.is_match(input),
        None => {
            SHARE_RE_256.is_match(input) ||
            SHARE_RE_192.is_match(input) ||
            SHARE_RE_128.is_match(input)
        },
        _ => false,
    };
    if is_valid {
        Ok(())
    } else {
        Err(MgmError::InvalidInput("Share format is invalid".to_string()))
    }
}