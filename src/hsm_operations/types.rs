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
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};
use crate::hsm_operations::algorithms;
use crate::hsm_operations::common::contains_all;

#[derive(Clone, Debug)]
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
    pub fn new(
        id: u16,
        object_type: ObjectType,
        label: String,
        algorithm: ObjectAlgorithm,
        domains: Vec<ObjectDomain>,
        capabilities: Vec<ObjectCapability>,
        delegated_capabilities: Vec<ObjectCapability>,
        data: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            object_type,
            label,
            algorithm,
            domains,
            capabilities,
            delegated_capabilities,
            data,
        }
    }

    pub fn empty() -> Self {
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
        let mut dom_str = String::new().to_owned();
        self.domains.iter().for_each(|domain| dom_str.push_str(format!("{},", domain).as_str()));
        if !dom_str.is_empty() {
            dom_str.pop();
        }
        dom_str
    }
    pub fn get_capabilities_str(&self) -> String {
        let mut caps_str = String::new().to_owned();
        self.capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
        if !caps_str.is_empty() {
            caps_str.pop();
        }
        caps_str
    }
    pub fn get_delegated_capabilities_str(&self) -> String {
        let mut caps_str = String::new().to_owned();
        self.delegated_capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
        if !caps_str.is_empty() {
            caps_str.pop();
        }
        caps_str
    }
}






#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum MgmCommandType {
    #[default]
    List,
    Search,
    GetKeyProperties,
    Generate,
    Import,
    Delete,
    GetPublicKey,
    GetCertificate,
    Sign,
    Encrypt,
    Decrypt,
    DeriveEcdh,
    SetupUser,
    SetupAdmin,
    SetupAuditor,
    SetupBackupAdmin,
    SignAttestationCert,
    ExportWrapped,
    ImportWrapped,
    BackupDevice,
    RestoreDevice,
    GotoKey,
    GotoSpecialCase,
    GotoDevice,
    GetDeviceInfo,
    GetDevicePublicKey,
    GetRandom,
    Reset,
    Exit,
}

#[derive(Clone, Debug, Copy, PartialEq,  Eq, Default)]
pub struct MgmCommand {
    pub command: MgmCommandType,
    pub label: &'static str,
    pub description: &'static str,
    pub required_capabilities: &'static [ObjectCapability],
    pub require_all_capabilities: bool,
}

impl MgmCommand {

    pub const EXIT_COMMAND: MgmCommand = MgmCommand {
        command: MgmCommandType::Exit,
        label: "Exit YubiHSM Manager",
        description: "",
        required_capabilities: &[],
        require_all_capabilities: false,
    };

    pub fn new(
        command: MgmCommandType,
        label: &'static str,
        description: &'static str,
        required_capabilities: &'static [ObjectCapability],
        require_all_capabilities: bool,
    ) -> Self {
        Self {
            command,
            label,
            description,
            required_capabilities,
            require_all_capabilities,
        }
    }

    pub fn is_authkey_authorized(&self, authkey: &ObjectDescriptor) -> bool {
        if self.required_capabilities.is_empty() {
            return true;
        }
        if self.require_all_capabilities {
            contains_all(&authkey.capabilities, &self.required_capabilities)
        } else {
            self.required_capabilities.iter().any(|cap| authkey.capabilities.contains(cap))
        }
    }

    pub fn contains_command(
        commands: &[MgmCommand],
        commands_to_check: &MgmCommandType,
    ) -> bool {
        commands.iter().any(|cmd| cmd.command == *commands_to_check)
    }
}






#[derive(Debug, Clone, PartialEq,  Eq, Default)]
pub struct SelectionItem<T: Clone + Eq> {
    pub value: T,
    pub label: String,
    pub hint: String,
}

impl <T:Clone+Eq> SelectionItem<T> {
    pub fn new(value: T, label: String, hint: String) -> Self {
        SelectionItem { value, label, hint }
    }
}

// impl <T:Clone+Eq> From<&MgmAlgorithm> for SelectionItem<T> {
//     fn from(algorithm: &MgmAlgorithm) -> Self {
//         SelectionItem::new(
//             algorithm.algorithm(),
//             algorithm.label().to_string(),
//             algorithm.description().to_string(),
//         )
//     }
// }

impl <T:Clone+Eq+Display> SelectionItem<T> {
    pub fn get_item(value: &T) -> Self
    {
        SelectionItem::new(
            value.clone(),
            format!("{}", value),
            String::new(),
        )
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

    // pub fn get_algorithm_items(algorithms: &[MgmAlgorithm]) -> Vec<SelectionItem<MgmAlgorithm>>
    // {
    //     let mut items:Vec<SelectionItem<MgmAlgorithm>> = Vec::new();
    //     for algo in algorithms {
    //         items.push(Self::from(algo));
    //     }
    //     items
    // }

}
