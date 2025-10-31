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

use yubihsmrs::object::{ObjectAlgorithm, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::error::MgmError;

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AesMode {
    #[default]
    Ecb,
    Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum EncryptionMode {
    #[default]
    Encrypt,
    Decrypt,
}

pub fn get_sym_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let keys = session.list_objects_with_filter(
        0,
        ObjectType::SymmetricKey,
        "",
        ObjectAlgorithm::ANY,
        &Vec::new())?;
    Ok(keys)
}

pub fn generate(session:&Session, new_key:&ObjectDescriptor) -> Result<u16, MgmError> {
    Ok(session
        .generate_aes_key(
            new_key.id, &new_key.label, &new_key.capabilities, &new_key.domains, new_key.algorithm)?)
}

pub fn import(session:&Session, new_key:&ObjectDescriptor, key_data:&[u8]) -> Result<u16, MgmError> {
    let algo = get_algorithm_from_keylen(key_data.len())?;
    Ok(session
        .import_aes_key(
            new_key.id,
            &new_key.label,
            &new_key.domains,
            &new_key.capabilities,
            algo,
            key_data)?)
}

pub fn operate(session:&Session, operation_key:&ObjectDescriptor, aes_mode:AesMode, enc_mode:EncryptionMode, iv:&[u8], data:&[u8]) -> Result<Vec<u8>, MgmError> {
    let out_data = match enc_mode {
        EncryptionMode::Encrypt => {
            match aes_mode {
                AesMode::Ecb => session.encrypt_aes_ecb(operation_key.id, data)?,
                AesMode::Cbc => session.encrypt_aes_cbc(operation_key.id, iv, data)?
            }
        },
        EncryptionMode::Decrypt => {
            match aes_mode {
                AesMode::Ecb => session.decrypt_aes_ecb(operation_key.id, data)?,
                AesMode::Cbc => session.decrypt_aes_cbc(operation_key.id, iv, data)?
            }
        }
    };
    Ok(out_data)
}






pub fn get_algorithm_from_keylen(keylen: usize) -> Result<ObjectAlgorithm, MgmError> {
    match keylen {
        16 => Ok(ObjectAlgorithm::Aes128),
        24 => Ok(ObjectAlgorithm::Aes192),
        32 => Ok(ObjectAlgorithm::Aes256),
        _ => Err(MgmError::Error(format!("Unsupported key length {}", keylen))),
    }
}