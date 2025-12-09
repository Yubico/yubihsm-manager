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
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::validators::object_id_validator;
use crate::hsm_operations::types::MgmCommand;

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

pub fn get_object_descriptors(session: &Session, handlers: &[ObjectHandle]) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let descriptors: Vec<ObjectDescriptor> = handlers
        .iter()
        .map(|k| session.get_object_info(k.object_id, k.object_type))
        .collect::<Result<_, _>>()?;
    Ok(descriptors)
}

pub fn get_op_keys(
    session: &Session,
    authkey: &ObjectDescriptor,
    op_key_capabilities: &[ObjectCapability],
    op_key_type: ObjectType,
    op_key_algorithms: Option<&[ObjectAlgorithm]>) -> Result<Vec<ObjectDescriptor>, MgmError> {

    let mut caps = op_key_capabilities.to_vec();
    caps.retain(|c| authkey.capabilities.contains(c));
    if caps.is_empty() {
        let caps_str = op_key_capabilities.iter().map(|c| format!("{:?}", c)).collect::<Vec<String>>().join(", ");
        return Err(MgmError::Error(
            format!("Authentication key does not have required capabilities. Operation requires one of the capabilities: {}", caps_str)));
    }

    let keys = session.list_objects_with_filter(
        0,
        op_key_type,
        "",
        ObjectAlgorithm::ANY,
        &caps)?;
    if keys.is_empty() {
        let caps_str = caps.iter().map(|c| format!("{:?}", c)).collect::<Vec<String>>().join(", ");
        return Err(MgmError::Error(
            format!("No {} key with the required capabilities was found. Key must have one of the capabilities: {}", op_key_type, caps_str)));
    }

    let mut keys = get_object_descriptors(session, &keys)?;

    if let Some(algo) = op_key_algorithms {
        keys.retain(|desc| algo.contains(&desc.algorithm));
        if keys.is_empty() {
            let algo_str = algo.iter().map(|a| format!("{:?}", a)).collect::<Vec<String>>().join(", ");
            return Err(MgmError::Error(
                format!("No {} key with the required algorithms was found. Key must have one of the algorithms: {}", op_key_type, algo_str)));
        }
    }
    Ok(keys)
}