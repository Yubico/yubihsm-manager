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

use std::str::FromStr;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::backend_traits::YubihsmOperationsCommon;
use crate::backend::error::MgmError;
use crate::backend::validators::object_id_validator;
use crate::backend::types::MgmCommand;

pub fn get_id_from_string(id_str: &str) -> Result<u16, MgmError> {
    object_id_validator(id_str)?;
    let id = if let Some(hex) = id_str.strip_prefix("0x") {
        u16::from_str_radix(hex, 16).unwrap()
    } else {
        u16::from_str(id_str).unwrap()
    };
    Ok(id)
}

pub fn get_delegated_capabilities(object: &ObjectDescriptor) -> Vec<ObjectCapability>  {
    match &object.delegated_capabilities {
        Some(caps) => caps.clone(),
        None => Vec::new()
    }
}

pub fn get_op_keys(
    session: &Session,
    authkey: &ObjectDescriptor,
    op_key_capabilities: &[ObjectCapability],
    op_key_type: ObjectType,
    op_key_algorithms: Option<&[ObjectAlgorithm]>) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let mut caps = op_key_capabilities.to_vec();
    caps.retain(|c| authkey.capabilities.contains(c));

    let keys = session.list_objects_with_filter(
        0,
        op_key_type,
        "",
        ObjectAlgorithm::ANY,
        &caps)?;
    let mut keys = YubihsmOperationsCommon.get_object_descriptors(session, &keys)?;

    if let Some(item) = op_key_algorithms {
        keys.retain(|desc| item.contains(&desc.algorithm));
    }
    Ok(keys)
}

pub fn contains_all(set: &[ObjectCapability], subset: &[ObjectCapability]) -> bool {
    for c in subset {
        if !set.contains(c) {
            return false
        }
    }
    true
}

pub fn get_authorized_commands(
    authkey: &ObjectDescriptor,
    commands: &[MgmCommand],
) -> Vec<MgmCommand> {
    let mut authorized_commands = commands.to_vec();
    authorized_commands.retain(|cmd| {
        cmd.is_authkey_authorized(authkey)
    });
    authorized_commands
}