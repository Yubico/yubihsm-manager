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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::backend::types::YhAlgorithm;
use crate::error::MgmError;

pub fn get_descriptors_from_handlers(session:&Session, handlers: &[ObjectHandle]) -> Result<Vec<ObjectDescriptor>, MgmError> {
    let descriptors: Vec<ObjectDescriptor> = handlers
        .iter()
        .map(|k| session.get_object_info(k.object_id, k.object_type))
        .collect::<Result<_, _>>()?;
    Ok(descriptors)
}

pub fn delete_objects(session: &Session, objects: &Vec<ObjectDescriptor>) -> Vec<ObjectDescriptor> {
    let mut failed:Vec<ObjectDescriptor> = Vec::new();
    for object in objects {
        if session.delete_object(object.id, object.object_type).is_err() {
            failed.push(object.clone());
        }
    }
    failed
}

pub fn get_new_object_note(key_desc: &ObjectDescriptor) -> String {
    key_desc.to_string()
            .replace("Sequence:  0\t", "")
            .replace("Origin: Generated\t", "")
            .replace("\t", "\n")
}

pub fn get_delegated_capabilities(object: &ObjectDescriptor) -> Vec<ObjectCapability>  {
    match &object.delegated_capabilities {
        Some(caps) => caps.clone(),
        None => Vec::new()
    }
}

// pub fn get_authorized_keys(
//     session:&Session,
//     main_authorized_key: &ObjectDescriptor,
//     target_key_capabilities: &[ObjectCapability],
//     target_key_type: ObjectType,
//     target_key_algos: &[ObjectAlgorithm]) -> Result<Vec<ObjectDescriptor>, MgmError> {
//
//     let mut effective_caps = target_key_capabilities.to_vec();
//     effective_caps.retain(|c| main_authorized_key.capabilities.contains(c));
//     if effective_caps.is_empty() {
//         return Err(MgmError::Error("Authentication/Wrap key is missing necessary capabilities".to_string()))
//     }
//
//     let keys = session.list_objects_with_filter(
//         0,
//         target_key_type,
//         "",
//         ObjectAlgorithm::ANY,
//         &effective_caps)?;
//     if keys.is_empty() {
//         return Err(MgmError::Error("There are no keys available for operation. No keys with necessary capabilities are found".to_string()))
//     }
//     let mut keys = get_descriptors_from_handlers(session, &keys)?;
//
//     if !target_key_algos.is_empty() {
//         keys.retain(|desc| target_key_algos.contains(&desc.algorithm));
//     }
//     if keys.is_empty() {
//         return Err(MgmError::Error("There are no keys available for operation. No keys of expected algorithms are found".to_string()))
//     }
//
//     Ok(keys)
// }

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
    let mut keys = get_descriptors_from_handlers(session, &keys)?;

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

pub fn extract_algorithms(algorithms: &[YhAlgorithm]) -> Vec<ObjectAlgorithm> {
    let mut algos = Vec::new();
    for a in algorithms {
        algos.push(a.algorithm);
    }
    algos
}