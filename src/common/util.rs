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
use crate::common::error::MgmError;
use crate::common::validators::object_id_validator;


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

#[cfg(test)]
mod tests {
    use super::*;
    use yubihsmrs::object::{ObjectCapability, ObjectDescriptor};

    // ── get_id_from_string ──

    #[test]
    fn test_id_from_decimal() {
        assert_eq!(get_id_from_string("100").unwrap(), 100);
    }

    #[test]
    fn test_id_from_hex() {
        assert_eq!(get_id_from_string("0x64").unwrap(), 100);
    }

    #[test]
    fn test_id_zero() {
        assert_eq!(get_id_from_string("0").unwrap(), 0);
    }

    #[test]
    fn test_id_from_hex_zero() {
        assert_eq!(get_id_from_string("0x0000").unwrap(), 0);
    }

    #[test]
    fn test_id_max() {
        assert_eq!(get_id_from_string("0xffff").unwrap(), 65535);
    }

    #[test]
    fn test_id_non_numeric() {
        assert!(get_id_from_string("notanumber").is_err());
    }

    #[test]
    fn test_id_overflow() {
        assert!(get_id_from_string("99999").is_err());
    }

    // ── get_delegated_capabilities ──

    #[test]
    fn test_delegated_caps_some() {
        let mut desc = ObjectDescriptor::new();
        let caps = vec![ObjectCapability::SignPkcs, ObjectCapability::ExportWrapped];
        desc.delegated_capabilities = Some(caps.clone());
        assert_eq!(get_delegated_capabilities(&desc), caps);
    }

    #[test]
    fn test_delegated_caps_none() {
        let desc = ObjectDescriptor::new();
        assert!(get_delegated_capabilities(&desc).is_empty());
    }

    // ── contains_all ──

    #[test]
    fn test_contains_all_superset() {
        let set = vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::ExportWrapped,
            ObjectCapability::ImportWrapped,
        ];
        let subset = vec![ObjectCapability::SignPkcs, ObjectCapability::ExportWrapped];
        assert!(contains_all(&set, &subset));
    }

    #[test]
    fn test_contains_all_equal() {
        let set = vec![ObjectCapability::SignPkcs];
        assert!(contains_all(&set, &set));
    }

    #[test]
    fn test_contains_all_missing() {
        let set = vec![ObjectCapability::SignPkcs];
        let subset = vec![ObjectCapability::SignPkcs, ObjectCapability::ExportWrapped];
        assert!(!contains_all(&set, &subset));
    }

    #[test]
    fn test_contains_all_empty_subset() {
        let set = vec![ObjectCapability::SignPkcs];
        assert!(contains_all(&set, &[]));
    }

    #[test]
    fn test_contains_all_empty_set_nonempty_subset() {
        let subset = vec![ObjectCapability::SignPkcs];
        assert!(!contains_all(&[], &subset));
    }

    // ── get_authorized_commands ──

    #[test]
    fn test_authorized_commands_no_required_caps() {
        // Commands with no required capabilities should always be included
        let cmd = MgmCommand {
            command: crate::common::types::MgmCommandType::List,
            label: "List",
            description: "",
            required_capabilities: &[],
            require_all_capabilities: false,
        };
        let mut authkey = ObjectDescriptor::new();
        authkey.capabilities = vec![]; // no caps at all

        let result = get_authorized_commands(&authkey, &[cmd.clone()]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_authorized_commands_filters_unauthorized() {
        let cmd = MgmCommand {
            command: crate::common::types::MgmCommandType::Generate,
            label: "Generate",
            description: "",
            required_capabilities: &[ObjectCapability::GenerateAsymmetricKey],
            require_all_capabilities: false,
        };
        let mut authkey = ObjectDescriptor::new();
        authkey.capabilities = vec![]; // missing the required cap

        let result = get_authorized_commands(&authkey, &[cmd]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_authorized_commands_includes_authorized() {
        let cmd = MgmCommand {
            command: crate::common::types::MgmCommandType::Generate,
            label: "Generate",
            description: "",
            required_capabilities: &[ObjectCapability::GenerateAsymmetricKey],
            require_all_capabilities: false,
        };
        let mut authkey = ObjectDescriptor::new();
        authkey.capabilities = vec![ObjectCapability::GenerateAsymmetricKey];

        let result = get_authorized_commands(&authkey, &[cmd]);
        assert_eq!(result.len(), 1);
    }
}