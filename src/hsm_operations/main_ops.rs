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
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::common::algorithms::MgmAlgorithm;
use crate::common::error::MgmError;
use crate::common::types::{NewObjectSpec, MgmCommand, MgmCommandType, SelectionItem};
use crate::common::util::{get_object_descriptors, get_authorized_commands};

#[derive(Debug, Clone, PartialEq,  Eq)]
pub enum FilterType {
    Id(u16),
    Label(String),
    Type(Vec<ObjectType>),
}

impl Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FilterType::Id(_) => write!(f, "By object ID"),
            FilterType::Label(_) => write!(f, "By object label"),
            FilterType::Type(_) => write!(f, "By object type"),
        }
    }
}

pub struct MainOperations;

impl YubihsmOperations for MainOperations {

    fn context(&self) -> &'static str {
        MainOperations::MAIN_CONTEXT
    }

    fn get_authorized_commands(&self, authkey: &ObjectDescriptor) -> Vec<MgmCommand> {
        get_authorized_commands(authkey, &Self::COMMANDS)
    }


    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let objects = session.list_objects()?;
        get_object_descriptors(session, &objects)
    }

    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm> {
        unimplemented!()
    }

    fn get_object_capabilities(&self, _object_type: Option<ObjectType>, _object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        unimplemented!()
    }

    fn generate(&self, _session: &Session, _spec: &NewObjectSpec) -> Result<u16, MgmError> {
        unimplemented!()
    }

    fn import(&self, _session: &Session, _spec: &NewObjectSpec) -> Result<u16, MgmError> {
        unimplemented!()
    }
}

impl MainOperations {

    pub const MAIN_CONTEXT: &'static str = "main";

    const COMMANDS: [MgmCommand; 8] = [
        MgmCommand {
            command: MgmCommandType::List,
            label: "List",
            description: "List all objects stored on the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        MgmCommand {
            command: MgmCommandType::Search,
            label: "Search objects",
            description: "Search for objects stored on the YubiHSM by ID, type or label",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        MgmCommand {
            command: MgmCommandType::Delete,
            label: "Delete",
            description: "Delete an object from the YubiHSM",
            required_capabilities: &[
                ObjectCapability::DeleteAsymmetricKey,
                ObjectCapability::DeleteOpaque,
                ObjectCapability::DeleteOpaque,
                ObjectCapability::DeleteSymmetricKey,
                ObjectCapability::DeleteWrapKey,
                ObjectCapability::DeletePublicWrapKey,
                ObjectCapability::DeleteAuthenticationKey],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::Generate,
            label: "Generate",
            description: "Generate a new key inside the YubiHSM",
            required_capabilities: &[
                ObjectCapability::GenerateAsymmetricKey,
                ObjectCapability::GenerateSymmetricKey,
                ObjectCapability::GenerateWrapKey],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::Import,
            label: "Import",
            description: "Import an object into the YubiHSM",
            required_capabilities: &[
                ObjectCapability::PutAsymmetricKey,
                ObjectCapability::PutOpaque,
                ObjectCapability::PutSymmetricKey,
                ObjectCapability::PutWrapKey,
                ObjectCapability::PutPublicWrapKey],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::GotoKey,
            label: "Goto key operation",
            description: "",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::GotoDevice,
            label: "Goto device operations",
            description: "Get pseudo random number, backup, restore or reset device",
            required_capabilities: &[
                ObjectCapability::GetPseudoRandom,
                ObjectCapability::ExportWrapped,
                ObjectCapability::ImportWrapped
            ],
            require_all_capabilities: false,
        },
        MgmCommand::EXIT_COMMAND,
    ];

    pub fn get_filtered_objects(session: &Session, filter: FilterType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let objects =
        match filter {
            FilterType::Id(id) => {
                let handles = session.list_objects_with_filter(id, ObjectType::Any, "", ObjectAlgorithm::ANY, &[])?;
                get_object_descriptors(session, &handles)?
            },
            FilterType::Type(types) => {
                let mut objects = Self.get_all_objects(session)?;
                objects.retain(|obj| types.contains(&obj.object_type));
                if types.contains(&ObjectType::Opaque) {
                    objects.retain(|obj| obj.object_type != ObjectType::Opaque || obj.algorithm == ObjectAlgorithm::OpaqueX509Certificate);
                }
                objects
            },
            FilterType::Label(label) => {
                let handles = session.list_objects_with_filter(0, ObjectType::Any, label.as_str(), ObjectAlgorithm::ANY, &[])?;
                get_object_descriptors(session, &handles)?
            },
        };
        Ok(objects)
    }

    pub fn get_objects_for_delete(session: &Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut objects = Self.get_all_objects(session)?;
        objects.retain(|obj| {
                match obj.object_type {
                    ObjectType::AsymmetricKey => authkey.capabilities.contains(&ObjectCapability::DeleteAsymmetricKey),
                    ObjectType::Opaque => authkey.capabilities.contains(&ObjectCapability::DeleteOpaque),
                    ObjectType::SymmetricKey => authkey.capabilities.contains(&ObjectCapability::DeleteSymmetricKey),
                    ObjectType::WrapKey => authkey.capabilities.contains(&ObjectCapability::DeleteWrapKey),
                    ObjectType::PublicWrapKey => authkey.capabilities.contains(&ObjectCapability::DeletePublicWrapKey),
                    ObjectType::AuthenticationKey => authkey.capabilities.contains(&ObjectCapability::DeleteAuthenticationKey),
                    _ => false,
                }
            });
        Ok(objects)
    }

    pub fn get_searchable_types() -> Vec<SelectionItem<ObjectType>> {
        vec![
            SelectionItem {
                value: ObjectType::AsymmetricKey,
                label: "Asymmetric key".to_string(),
                description: String::new()
            },
             SelectionItem {
                value: ObjectType::SymmetricKey,
                label: "Symmetric key".to_string(),
                description: String::new()
            }, SelectionItem {
                value: ObjectType::Opaque,
                label: "X509Certificate".to_string(),
                description: String::new()
            },
             SelectionItem {
                value: ObjectType::WrapKey,
                label: "Wrap key".to_string(),
                description: String::new()
            },
            SelectionItem {
                value: ObjectType::PublicWrapKey,
                label: "Public wrap key".to_string(),
                description: String::new()
            },
             SelectionItem {
                value: ObjectType::AuthenticationKey,
                label: "Authentication key".to_string(),
                description: String::new()
            },
        ]
    }

    pub fn get_generatable_types(authkey: &ObjectDescriptor) -> Vec<SelectionItem<ObjectType>> {
        let mut types = Vec::new();
        if authkey.capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) {
            types.push(SelectionItem {
                value: ObjectType::AsymmetricKey,
                label: "Asymmetric private key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities.contains(&ObjectCapability::GenerateSymmetricKey) {
            types.push(SelectionItem {
                value: ObjectType::SymmetricKey,
                label: "Symmetric key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities.contains(&ObjectCapability::GenerateWrapKey) {
            types.push(SelectionItem {
                value: ObjectType::WrapKey,
                label: "Wrap key".to_string(),
                description: String::new()
            });
        }
        types
    }


    pub fn get_importable_types(authkey: &ObjectDescriptor) -> Vec<SelectionItem<ObjectType>> {
        let mut types = Vec::new();
        if authkey.capabilities.contains(&ObjectCapability::PutAsymmetricKey) ||
            authkey.capabilities.contains(&ObjectCapability::PutOpaque) {
            types.push(SelectionItem {
                value: ObjectType::AsymmetricKey,
                label: "Asymmetric object".to_string(),
                description: "Asymmetric private key or X509Certificate".to_string()
            });
        }
        if authkey.capabilities.contains(&ObjectCapability::PutSymmetricKey) {
            types.push(SelectionItem {
                value: ObjectType::SymmetricKey,
                label: "Symmetric key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities.contains(&ObjectCapability::PutWrapKey) ||
            authkey.capabilities.contains(&ObjectCapability::PutPublicWrapKey) {
            types.push(SelectionItem {
                value: ObjectType::WrapKey,
                label: "Wrap key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities.contains(&ObjectCapability::PutAuthenticationKey) {
            types.push(SelectionItem {
                value: ObjectType::AuthenticationKey,
                label: "Authentication key".to_string(),
                description: String::new()
            });
        }
        types
    }

    pub fn get_key_operation_types() -> Vec<SelectionItem<MgmCommandType>> {
        vec![
            SelectionItem {
                value: MgmCommandType::GotoAsym,
                label: "Asymmetric key operations".to_string(),
                description: "Management and use of asymmetric keys and certificates, including attestation and certificate signing".to_string()
            },
             SelectionItem {
                value: MgmCommandType::GotoSym,
                label: "Symmetric key operations".to_string(),
                description: "Management and use of symmetric keys. Require firmware version 2.4 or higher".to_string()
            },
            SelectionItem {
                value: MgmCommandType::GotoWrap,
                label: "Wrap key operations".to_string(),
                description: "Management and use of wrap keys, including key export and import".to_string()
            },
             SelectionItem {
                value: MgmCommandType::GotoAuth,
                label: "Authentication key operations".to_string(),
                description: "Management of authentication keys (access control)".to_string()
            },
            SelectionItem {
                value: MgmCommandType::GotoJava,
                label: "Special operations: SunPKCS11".to_string(),
                description: "Management of keys compatible with SunPKCS11 provider".to_string()
            },
            SelectionItem {
                value: MgmCommandType::GotoKsp,
                label: "Special operations: KSP setup".to_string(),
                description: "Guided setup of the YubiHSM for Windows KSP/CNG provider".to_string()
            },
        ]
    }

}