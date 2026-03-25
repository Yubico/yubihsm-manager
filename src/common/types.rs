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

use std::fmt;
use std::fmt::Display;
use serde::{Serialize, Deserialize};
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};
use crate::common::algorithms;

pub const EXIT_LABEL: &str = "Exit YubiHSM Manager";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NewObjectSpec {
    pub id: u16,
    pub object_type: ObjectType,
    pub label: String,
    pub algorithm: ObjectAlgorithm,
    pub domains: Vec<ObjectDomain>,
    pub capabilities: Vec<ObjectCapability>,
    pub delegated_capabilities: Vec<ObjectCapability>,
    pub data: Vec<Vec<u8>>,
}

impl Display for NewObjectSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut spec_str = String::new().to_owned();
        spec_str.push_str(format!("ID: 0x{:04x?}\n", self.id).as_str());
        spec_str.push_str(format!("Type: {:16}\n", self.object_type).as_str());
        spec_str.push_str(format!("Label: {:40}\n", self.label).as_str());
        spec_str.push_str(format!("Algorithm: {:24}\n", self.algorithm).as_str());
        spec_str.push_str(format!("Domains: {:40}\n", self.get_domains_str()).as_str());
        spec_str.push_str(format!("Capabilities: {}\n", self.get_capabilities_str()).as_str());
        if [ObjectType::AuthenticationKey, ObjectType::WrapKey, ObjectType::PublicWrapKey].contains(&self.object_type) {
            spec_str.push_str(format!("Delegated capabilities: {}\n", self.get_delegated_capabilities_str()).as_str());
        }
        write!(f, "{}", spec_str)
    }
}

impl From<ObjectDescriptor> for NewObjectSpec {
    fn from(spec: ObjectDescriptor) -> Self {
        NewObjectSpec {
            id: spec.id,
            object_type: spec.object_type,
            label: spec.label,
            algorithm: spec.algorithm,
            domains: spec.domains,
            capabilities: spec.capabilities,
            delegated_capabilities: if spec.delegated_capabilities.is_some() {
                spec.delegated_capabilities.unwrap()
            } else {
                vec![]
            },
            data: vec![],
        }
    }
}

impl From<NewObjectSpec> for ObjectDescriptor {
    fn from(spec: NewObjectSpec) -> Self {
        let mut desc = ObjectDescriptor::new();
        desc.id = spec.id;
        desc.object_type = spec.object_type;
        desc.label = spec.label;
        desc.algorithm = spec.algorithm;
        desc.domains = spec.domains;
        desc.capabilities = spec.capabilities;
        desc.delegated_capabilities = if spec.delegated_capabilities.is_empty() {
            None
        } else {
            Some(spec.delegated_capabilities)
        };
        desc
    }
}

impl NewObjectSpec {

    pub fn new() -> Self {
        Self {
            id: 0,
            object_type: ObjectType::Any,
            label: String::new(),
            algorithm: ObjectAlgorithm::ANY,
            domains: vec![],
            capabilities: vec![],
            delegated_capabilities: vec![],
            data: vec![],
        }
    }

    pub fn get_id_str(&self) -> String {
        format!("0x{:04x}", self.id)
    }
    pub fn get_type_str(&self) -> String {
        format!("{:?}", self.object_type)
    }
    pub fn get_algorithm_str(&self) -> String {
        let mgm_algorithm = algorithms::MgmAlgorithm::from(self.algorithm);
        format!("{:?}", mgm_algorithm.label())
        // format!("{:?}", algorithms::MgmAlgorithm::from(self.algorithm).label())
        // format!("{:?}", self.algorithm)
    }
    pub fn get_domains_str(&self) -> String {
        self.domains.iter().map(|d| format!("{}", d)).collect::<Vec<String>>().join(",")
    }
    pub fn get_capabilities_str(&self) -> String {
        self.capabilities.iter().map(|c| format!("{:?}", c)).collect::<Vec<String>>().join(",")
    }
    pub fn get_delegated_capabilities_str(&self) -> String {
        self.delegated_capabilities.iter().map(|c| format!("{:?}", c)).collect::<Vec<String>>().join(",")
    }
}







#[derive(Debug, Clone, PartialEq,  Eq, Default)]
pub struct SelectionItem<T: Clone + Eq> {
    pub value: T,
    pub label: String,
    pub description: String,
}

impl <T:Clone+Eq+Display> SelectionItem<T> {
    pub fn get_item(value: &T) -> Self
    {
        SelectionItem {
            value: value.clone(),
            label: format!("{}", value),
            description: String::new(),
        }
    }

    pub fn get_items(values: &[T]) -> Vec<SelectionItem<T>>
    where T: Clone + Eq
    {
        let mut items:Vec<SelectionItem<T>> = Vec::new();
        for t in values {
            items.push(Self::get_item(t));
        }
        items
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yubihsmrs::object::{
        ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType,
    };

    // ── Helper: build a fully populated NewObjectSpec ──

    fn make_spec() -> NewObjectSpec {
        NewObjectSpec {
            id: 0x1234,
            object_type: ObjectType::AsymmetricKey,
            label: "test-key".to_string(),
            algorithm: ObjectAlgorithm::Rsa2048,
            domains: vec![ObjectDomain::One, ObjectDomain::Three],
            capabilities: vec![ObjectCapability::SignPkcs, ObjectCapability::SignPss],
            delegated_capabilities: vec![ObjectCapability::ExportWrapped],
            data: vec![vec![0xDE, 0xAD]],
        }
    }

    fn make_authkey_desc(caps: Vec<ObjectCapability>) -> ObjectDescriptor {
        let mut desc = ObjectDescriptor::new();
        desc.id = 1;
        desc.object_type = ObjectType::AuthenticationKey;
        desc.capabilities = caps;
        desc
    }

    // ══════════════════════════════════════════════
    //  NewObjectSpec construction
    // ══════════════════════════════════════════════

    #[test]
    fn test_new_object_spec_fields() {
        let spec = make_spec();
        assert_eq!(spec.id, 0x1234);
        assert_eq!(spec.object_type, ObjectType::AsymmetricKey);
        assert_eq!(spec.label, "test-key");
        assert_eq!(spec.algorithm, ObjectAlgorithm::Rsa2048);
        assert_eq!(spec.domains.len(), 2);
        assert_eq!(spec.capabilities.len(), 2);
        assert_eq!(spec.delegated_capabilities.len(), 1);
        assert_eq!(spec.data.len(), 1);
    }

    #[test]
    fn test_empty_spec() {
        let spec = NewObjectSpec::new();
        assert_eq!(spec.id, 0);
        assert_eq!(spec.object_type, ObjectType::Any);
        assert!(spec.label.is_empty());
        assert_eq!(spec.algorithm, ObjectAlgorithm::ANY);
        assert!(spec.domains.is_empty());
        assert!(spec.capabilities.is_empty());
        assert!(spec.delegated_capabilities.is_empty());
        assert!(spec.data.is_empty());
    }

    // ══════════════════════════════════════════════
    //  String formatting helpers
    // ══════════════════════════════════════════════

    #[test]
    fn test_get_id_str_low() {
        let mut spec = NewObjectSpec::new();
        spec.id = 1;
        assert_eq!(spec.get_id_str(), "0x0001");
    }

    #[test]
    fn test_formatting() {
        let spec = make_spec();
        assert_eq!(spec.get_id_str(), "0x1234");
        assert_eq!(spec.get_type_str(), "AsymmetricKey");
        assert_eq!(spec.get_algorithm_str(), "\"RSA 2048\"");
        assert_eq!(spec.get_domains_str(), "1,3");
        assert_eq!(spec.get_capabilities_str(), "sign-pkcs,sign-pss");
        assert_eq!(spec.get_delegated_capabilities_str(), "export-wrapped");
    }

    #[test]
    fn test_formatting_empty() {
        let spec = NewObjectSpec::new();
        assert!(spec.get_domains_str().is_empty());
        assert!(spec.get_delegated_capabilities_str().is_empty());
    }

    // ══════════════════════════════════════════════
    //  Display trait
    // ══════════════════════════════════════════════

    #[test]
    fn test_display_delegated() {

        // AsymmetricKey and SymmetricKey should NOT include "Delegated capabilities:" line

        let mut spec = make_spec();
        let output = format!("{}", spec);
        assert!(
            !output.contains("Delegated capabilities:"),
            "Display should not contain delegated capabilities for AsymmetricKey. Output: {}", output
        );

        spec.object_type = ObjectType::SymmetricKey;
        let output = format!("{}", spec);
        assert!(
            !output.contains("Delegated capabilities:"),
            "Display should not contain delegated capabilities for SymmetricKey. Output: {}", output
        );

        // AuthenticationKey, WrapKey and PublicWrapKey should NOT include "Delegated capabilities:" line

        spec.object_type = ObjectType::AuthenticationKey;
        let output = format!("{}", spec);
        assert!(
            output.contains("Delegated capabilities:"),
            "Display should contain delegated capabilities for AuthenticationKey. Output: {}", output
        );

        spec.object_type = ObjectType::WrapKey;
        let output = format!("{}", spec);
        assert!(
            output.contains("Delegated capabilities:"),
            "Display should contain delegated capabilities for WrapKey. Output: {}", output
        );

        spec.object_type = ObjectType::PublicWrapKey;
        let output = format!("{}", spec);
        assert!(
            output.contains("Delegated capabilities:"),
            "Display should contain delegated capabilities for PublicWrapKey. Output: {}", output
        );

    }

    // ══════════════════════════════════════════════
    //  From<ObjectDescriptor> for NewObjectSpec
    // ══════════════════════════════════════════════

    #[test]
    fn test_from_descriptor_basic_fields() {
        let mut desc = ObjectDescriptor::new();
        desc.id = 0x0042;
        desc.object_type = ObjectType::SymmetricKey;
        desc.label = "sym-key".to_string();
        desc.algorithm = ObjectAlgorithm::Aes128;
        desc.domains = vec![ObjectDomain::Two];
        desc.capabilities = vec![ObjectCapability::EncryptCbc];
        desc.delegated_capabilities = Some(vec![ObjectCapability::ImportWrapped]);

        let spec: NewObjectSpec = NewObjectSpec::from(desc);
        assert_eq!(spec.id, 0x0042);
        assert_eq!(spec.object_type, ObjectType::SymmetricKey);
        assert_eq!(spec.label, "sym-key");
        assert_eq!(spec.algorithm, ObjectAlgorithm::Aes128);
        assert_eq!(spec.domains, vec![ObjectDomain::Two]);
        assert_eq!(spec.capabilities, vec![ObjectCapability::EncryptCbc]);
        assert_eq!(
            spec.delegated_capabilities,
            vec![ObjectCapability::ImportWrapped]
        );
        // data is always empty when converting from ObjectDescriptor
        assert!(spec.data.is_empty());
    }

    #[test]
    fn test_from_descriptor_delegated_none() {
        let mut desc = ObjectDescriptor::new();
        desc.delegated_capabilities = None;

        let spec = NewObjectSpec::from(desc);
        assert!(spec.delegated_capabilities.is_empty());
    }

    // ══════════════════════════════════════════════
    //  From<NewObjectSpec> for ObjectDescriptor
    // ══════════════════════════════════════════════

    #[test]
    fn test_to_descriptor_basic_fields() {
        let spec = make_spec();
        let desc: ObjectDescriptor = spec.into();
        assert_eq!(desc.id, 0x1234);
        assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
        assert_eq!(desc.label, "test-key");
        assert_eq!(desc.algorithm, ObjectAlgorithm::Rsa2048);
        assert_eq!(desc.domains, vec![ObjectDomain::One, ObjectDomain::Three]);
        assert_eq!(
            desc.capabilities,
            vec![ObjectCapability::SignPkcs, ObjectCapability::SignPss]
        );
        assert_eq!(
            desc.delegated_capabilities,
            Some(vec![ObjectCapability::ExportWrapped])
        );
    }

    #[test]
    fn test_to_descriptor_empty_delegated_becomes_none() {
        let mut spec = make_spec();
        spec.delegated_capabilities = vec![];
        let desc: ObjectDescriptor = spec.into();
        assert_eq!(desc.delegated_capabilities, None);
    }

    // ══════════════════════════════════════════════
    //  MgmCommand::is_authkey_authorized
    // ══════════════════════════════════════════════

    #[test]
    fn test_authz_no_required_caps_always_true() {
        let cmd = MgmCommand {
            command: MgmCommandType::List,
            label: "List",
            description: "",
            required_capabilities: &[],
            require_all_capabilities: false,
        };
        let authkey = make_authkey_desc(vec![]);
        assert!(cmd.is_authkey_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_all_has_all() {
        let cmd = MgmCommand {
            command: MgmCommandType::Generate,
            label: "Generate",
            description: "",
            required_capabilities: &[
                ObjectCapability::GenerateAsymmetricKey,
                ObjectCapability::SignPkcs,
            ],
            require_all_capabilities: true,
        };
        let authkey = make_authkey_desc(vec![
            ObjectCapability::GenerateAsymmetricKey,
            ObjectCapability::SignPkcs,
            ObjectCapability::ExportWrapped, // extra cap is fine
        ]);
        assert!(cmd.is_authkey_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_all_missing_one() {
        let cmd = MgmCommand {
            command: MgmCommandType::Generate,
            label: "Generate",
            description: "",
            required_capabilities: &[
                ObjectCapability::GenerateAsymmetricKey,
                ObjectCapability::SignPkcs,
            ],
            require_all_capabilities: true,
        };
        // Missing SignPkcs
        let authkey = make_authkey_desc(vec![ObjectCapability::GenerateAsymmetricKey]);
        assert!(!cmd.is_authkey_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_any_has_one() {
        let cmd = MgmCommand {
            command: MgmCommandType::Sign,
            label: "Sign",
            description: "",
            required_capabilities: &[
                ObjectCapability::SignPkcs,
                ObjectCapability::SignPss,
                ObjectCapability::SignEcdsa,
            ],
            require_all_capabilities: false,
        };
        // Only has SignPss — that's enough with require_all=false
        let authkey = make_authkey_desc(vec![ObjectCapability::SignPss]);
        assert!(cmd.is_authkey_authorized(&authkey));
    }

    #[test]
    fn test_authz_require_any_has_none() {
        let cmd = MgmCommand {
            command: MgmCommandType::Sign,
            label: "Sign",
            description: "",
            required_capabilities: &[
                ObjectCapability::SignPkcs,
                ObjectCapability::SignPss,
            ],
            require_all_capabilities: false,
        };
        // Has completely unrelated capabilities
        let authkey = make_authkey_desc(vec![ObjectCapability::ExportWrapped]);
        assert!(!cmd.is_authkey_authorized(&authkey));
    }

    // ══════════════════════════════════════════════
    //  MgmCommand::contains_command
    // ══════════════════════════════════════════════

    #[test]
    fn test_contains_command() {
        let commands = vec![
            MgmCommand {
                command: MgmCommandType::List,
                label: "List",
                description: "",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Generate,
                label: "Generate",
                description: "",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
        ];
        assert!(MgmCommand::contains_command(&commands, &MgmCommandType::List));
        assert!(MgmCommand::contains_command(&commands, &MgmCommandType::Generate));
        assert!(!MgmCommand::contains_command(&commands, &MgmCommandType::Delete));
    }

    #[test]
    fn test_contains_command_empty_list() {
        assert!(!MgmCommand::contains_command(&[], &MgmCommandType::List));
    }

    // ══════════════════════════════════════════════
    //  SelectionItem
    // ══════════════════════════════════════════════

    #[test]
    fn test_selection_item_new() {
        let item = SelectionItem {
            value: 42u32,
            label: "forty-two".to_string(),
            description: "a hint".to_string() };
        assert_eq!(item.value, 42);
        assert_eq!(item.label, "forty-two");
        assert_eq!(item.description, "a hint");
    }

    #[test]
    fn test_selection_item_get_item() {
        // String implements Display, so we can use get_item
        let item = SelectionItem::get_item(&"hello".to_string());
        assert_eq!(item.value, "hello");
        assert_eq!(item.label, "hello");
        assert!(item.description.is_empty());
    }

    #[test]
    fn test_selection_item_get_items() {
        let values = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let items = SelectionItem::get_items(&values);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].value, "alpha");
        assert_eq!(items[1].value, "beta");
        assert_eq!(items[2].value, "gamma");
    }

    #[test]
    fn test_selection_item_get_items_empty() {
        let values: Vec<String> = vec![];
        let items = SelectionItem::get_items(&values);
        assert!(items.is_empty());
    }
}