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

use std::fs::File;
use std::io::{Read};
use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::backend::common::{get_delegated_capabilities, get_descriptors_from_handlers};
use crate::error::MgmError;

// 2 object ID bytes + 2 domains bytes + 8 capabilities bytes + 8 delegated capabilities = 20 bytes
const WRAP_SPLIT_PREFIX_LEN: usize = 20;

pub struct WrapKeyShares {
    pub number_of_shares: u8,
    pub threshold: u8,
    pub shares: Vec<String>,
}

pub struct WrappedKey {
    pub object_id: u16,
    pub object_type: ObjectType,
    pub wrapping_key_id: u16,
    pub wrapped_data: Vec<u8>,
    pub error: Option<MgmError>,
}


pub fn get_wrap_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    Ok(session.list_objects_with_filter(
        0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?)
}

pub fn get_exportable_objects(session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let objects = session.list_objects_with_filter(
        0,
        ObjectType::Any,
        "",
        ObjectAlgorithm::ANY,
        &[ObjectCapability::ExportableUnderWrap])?;
    let objects = get_descriptors_from_handlers(session, objects.as_slice())?;
    Ok(objects)
}

pub fn generate_wrap_key(session:&Session, new_key:&ObjectDescriptor) -> Result<u16, MgmError> {
    let id = session
        .generate_wrap_key(
            new_key.id,
            &new_key.label,
            &new_key.domains,
            &new_key.capabilities,
            new_key.algorithm,
            get_delegated_capabilities(&new_key).as_slice())?;
    Ok(id)
}

pub fn import_wrap_key(session:&Session, new_key:&ObjectDescriptor, key_data:&[u8]) -> Result<u16, MgmError> {
    let algo = get_algorithm_from_keylen(key_data.len())?;
    let id = session
        .import_wrap_key(
            new_key.id,
            &new_key.label,
            &new_key.domains,
            &new_key.capabilities,
            algo,
            get_delegated_capabilities(&new_key).as_slice(),
            key_data)?;
    Ok(id)
}

pub fn split_wrap_key(wrap_desc:&ObjectDescriptor, threshold:u8, shares:u8, key_data:&[u8]) -> Result<WrapKeyShares, MgmError> {
    let mut split_key = WrapKeyShares {
        number_of_shares: shares,
        threshold,
        shares: Vec::new(),
    };

    let mut data = Vec::<u8>::new();
    data.push(((wrap_desc.id >> 8) & 0xff) as u8);
    data.push((wrap_desc.id & 0xff) as u8);
    data.append(&mut ObjectDomain::bytes_from_slice(wrap_desc.domains.as_slice()));
    data.append(&mut ObjectCapability::bytes_from_slice(wrap_desc.capabilities.as_slice()));
    data.append(&mut ObjectCapability::bytes_from_slice(get_delegated_capabilities(wrap_desc).as_slice()));
    data.extend_from_slice(key_data);

    split_key.shares = rusty_secrets::generate_shares(threshold, shares, &data)?;

    Ok(split_key)
}

pub fn get_wrapkey_from_shares(shares:Vec<String>) -> Result<(ObjectDescriptor, Vec<u8>), MgmError> {
    let data = rusty_secrets::recover_secret(shares)?;

    let key_len = data.len() - WRAP_SPLIT_PREFIX_LEN;

    if data.len() != WRAP_SPLIT_PREFIX_LEN + (key_len) {
        return Err(MgmError::Error(format!(
            "Wrong length for recovered secret: expected {}, found {}",
            WRAP_SPLIT_PREFIX_LEN + (key_len / 8),
            data.len()
        )));
    }

    let mut wrapkey_desc = ObjectDescriptor::new();
    wrapkey_desc.object_type = ObjectType::WrapKey;
    wrapkey_desc.algorithm = get_algorithm_from_keylen(key_len)?;
    wrapkey_desc.id = ((u16::from(data[0])) << 8) | u16::from(data[1]);
    wrapkey_desc.domains = ObjectDomain::from_bytes(&data[2..4])?;
    wrapkey_desc.capabilities = ObjectCapability::from_bytes(&data[4..12])?;
    let delegated = ObjectCapability::from_bytes(&data[12..20])?;
    wrapkey_desc.delegated_capabilities = if delegated.is_empty() { None } else { Some(delegated) };

    let wrapkey_data = data[20..].to_vec();

    Ok((wrapkey_desc, wrapkey_data))
}

pub fn export_wrapped(session:&Session, wrapkey:u16, export_objects:&Vec<ObjectDescriptor>) -> Result<Vec<WrappedKey>, MgmError> {
    let mut res = Vec::new();
    for object in export_objects {
        let mut wrapped_key = WrappedKey {
            object_id: object.id,
            object_type: object.object_type,
            wrapping_key_id: wrapkey,
            wrapped_data: Vec::new(),
            error: None,
        };
        match session.export_wrapped(wrapkey, object.object_type, object.id) {
            Ok(bytes) => wrapped_key.wrapped_data = bytes,
            Err(err) => wrapped_key.error = Some(MgmError::LibYubiHsm(err))

        }
        res.push(wrapped_key);
    }
    return Ok(res)
}

pub fn import_wrapped(session: &Session, wrapkey_id: u16, filepath: &str) -> Result<WrappedKey, MgmError> {
    if !filepath.ends_with(".yhw") {
        return Err(MgmError::Error("File must have a .yhw extension".to_string()));
    }
    let mut file = File::open(&filepath)?;

    let mut wrapped = String::new();
    file.read_to_string(&mut wrapped)?;
    if wrapped.is_empty() {
        return Err(MgmError::Error(format!("File {} is empty", filepath)));
    }

    let mut import_key = WrappedKey {
        object_id: 0,
        object_type: ObjectType::Any,
        wrapping_key_id: wrapkey_id,
        wrapped_data: Vec::new(),
        error: None,
    };

    let data = base64::decode_block(&wrapped)?;
    match  session.import_wrapped(wrapkey_id, &data) {
            Ok(o) => {
                import_key.object_id = o.object_id;
                import_key.object_type = o.object_type;
            },
            Err(err) => {
                import_key.error = Some(MgmError::Error(format!(
                    "Failed to import the content of file {}: {}",
                    filepath,
                    err
                )))
            }
    }

    Ok(import_key)
}

pub fn backup_device(session: &Session, wrapkey_id: u16) -> Result<Vec<WrappedKey>, MgmError> {
    let objects = get_exportable_objects(session)?;
    export_wrapped(session, wrapkey_id, &objects)
}

pub fn restore_device(session: &Session, wrapkey_id: u16, directory: &str) -> Result<Vec<WrappedKey>, MgmError> {
    let files: Vec<_> = match scan_dir::ScanDir::files().read(directory, |iter| {
        iter.filter(|(_, name)| name.ends_with(".yhw")).map(|(entry, _)| entry.path()).collect()
    }) {
        Ok(f) => f,
        Err(err) => {
            return Err(MgmError::Error(format!("Failed to read files. {}", err)));
        }
    };

    if files.is_empty() {
        return Ok(Vec::new());
    }

    let mut res = Vec::new();

    for f in files {
        if f.to_str().is_none() {
            continue;
        }

        res.push(import_wrapped(session, wrapkey_id, f.to_str().unwrap())?);
    }
    Ok(res)
}

pub fn get_algorithm_from_keylen(keylen: usize) -> Result<ObjectAlgorithm, MgmError> {
    match keylen {
        16 => Ok(ObjectAlgorithm::Aes128CcmWrap),
        24 => Ok(ObjectAlgorithm::Aes192CcmWrap),
        32 => Ok(ObjectAlgorithm::Aes256CcmWrap),
        _ => Err(MgmError::Error(format!("Unsupported key length {}", keylen))),
    }
}




