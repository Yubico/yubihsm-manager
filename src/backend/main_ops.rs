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
use crate::backend::error::MgmError;
use crate::backend::asym::{AsymOps, JavaOps};
use crate::backend::sym::SymOps;
use crate::backend::wrap::WrapOps;
use crate::backend::object_ops::Deletable;
use crate::backend::common::{get_descriptors_from_handlers, get_authorized_commands};
use crate::backend::types::{MgmCommand, MgmCommandType};

#[derive(Debug, Clone, PartialEq,  Eq, Default)]
pub enum FilterType {
    #[default]
    All,
    Id(u16),
    Type(Vec<MgmObjectType>),
    Label(String),
}

impl Display for FilterType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FilterType::All => write!(f, "List all objects"),
            FilterType::Id(_) => write!(f, "Filter by object ID"),
            FilterType::Type(_) => write!(f, "Filter by object type"),
            FilterType::Label(_) => write!(f, "Filter by object label"),
        }
    }
}

#[derive(Debug, Clone, PartialEq,  Eq)]
pub enum MgmObjectType {
    Asymmetric,
    Symmetric,
    Certificate,
    Wrap,
    Authentication,
    Java,
    Ksp
}

impl Display for MgmObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MgmObjectType::Asymmetric => write!(f, "Asymmetric object"),
            MgmObjectType::Symmetric => write!(f, "Symmetric key"),
            MgmObjectType::Certificate => write!(f, "X509Certificate object"),
            MgmObjectType::Wrap => write!(f, "Wrap key"),
            MgmObjectType::Authentication => write!(f, "Authentication key"),
            MgmObjectType::Java => write!(f, "Special case: SunPKCS11 compatible key"),
            MgmObjectType::Ksp => write!(f, "Special case: KSP setup"),

        }
    }
}

impl Into<ObjectType> for MgmObjectType {
    fn into(self) -> ObjectType {
        match self {
            MgmObjectType::Asymmetric => ObjectType::AsymmetricKey,
            MgmObjectType::Symmetric => ObjectType::SymmetricKey,
            MgmObjectType::Certificate => ObjectType::Opaque,
            MgmObjectType::Wrap => ObjectType::WrapKey,
            MgmObjectType::Authentication => ObjectType::AuthenticationKey,
            MgmObjectType::Java => ObjectType::AsymmetricKey,
            MgmObjectType::Ksp => ObjectType::Any,
        }
    }
}



pub struct MainOps;

impl Deletable for MainOps {}

impl MainOps {
    const MAIN_COMMANDS: [MgmCommand;9] = [
        MgmCommand {
            command: MgmCommandType::List,
            label: "List",
            description: "List all objects stored on the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        MgmCommand {
            command: MgmCommandType::GetKeyProperties,
            label: "Get Object Properties",
            description: "Get properties of an object stored on the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
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
                ObjectCapability::PutWrapKey],
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
            command: MgmCommandType::GotoSpecialCase,
            label: "Goto special case operations",
            description: "",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::GotoDevice,
            label: "Goto device operations",
            description: "Get pseudo random number, backup, restore or reset device",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        MgmCommand::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<MgmCommand> {
        get_authorized_commands(authkey, &Self::MAIN_COMMANDS)
    }

    pub fn get_all_objects(session: &Session, filter: FilterType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let objects = session.list_objects()?;

        let f = if filter == FilterType::All {
            FilterType::Type([
                MgmObjectType::Asymmetric,
                MgmObjectType::Certificate,
                MgmObjectType::Symmetric,
                MgmObjectType::Certificate,
                MgmObjectType::Wrap,
                MgmObjectType::Authentication].to_vec())
        } else {
            filter
        };

        let mut objects = get_descriptors_from_handlers(session, &objects)?;
        match f {
            FilterType::Id(id) => {
                objects.retain(|obj| id == obj.id);
            },
            FilterType::Type(types) => {
                // let object_types: Vec<ObjectType> = types.iter().map(|t| <MgmObjectType as Into<ObjectType>>::into(t.to_owned())).collect();
                objects.retain(|obj| types.iter().any(|t| <MgmObjectType as Into<ObjectType>>::into(t.to_owned()) == obj.object_type));
                if types.contains(&MgmObjectType::Certificate) {
                    objects.retain(|obj| obj.object_type != ObjectType::Opaque || obj.algorithm == ObjectAlgorithm::OpaqueX509Certificate);
                }
            },
            FilterType::Label(label) => {
                objects.retain(|obj| obj.label == label);
            },
            _ => unreachable!()
        };
        Ok(objects)
    }

    pub fn get_objects_for_delete(session: &Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let all_objects = Self::get_all_objects(session, FilterType::All)?;
        let deletable_objects: Vec<ObjectDescriptor> = all_objects.into_iter()
            .filter(|obj| {
                match obj.object_type {
                    ObjectType::AsymmetricKey => authkey.capabilities.contains(&ObjectCapability::DeleteAsymmetricKey),
                    ObjectType::Opaque => authkey.capabilities.contains(&ObjectCapability::DeleteOpaque),
                    ObjectType::SymmetricKey => authkey.capabilities.contains(&ObjectCapability::DeleteSymmetricKey),
                    ObjectType::WrapKey => authkey.capabilities.contains(&ObjectCapability::DeleteWrapKey),
                    ObjectType::AuthenticationKey => authkey.capabilities.contains(&ObjectCapability::DeleteAuthenticationKey),
                    _ => false,
                }
            })
            .collect();
        Ok(deletable_objects)
    }

    pub fn get_filtrable_types() -> Vec<MgmObjectType> {
        vec![
            MgmObjectType::Asymmetric,
            MgmObjectType::Symmetric,
            MgmObjectType::Certificate,
            MgmObjectType::Wrap,
            MgmObjectType::Authentication,
        ]
    }

    pub fn get_generatable_types(authkey: &ObjectDescriptor) -> Vec<MgmObjectType> {
        let mut types = Vec::new();
        if MgmCommand::contains_command(&AsymOps::get_authorized_commands(authkey), &MgmCommandType::Generate) {
            types.push(MgmObjectType::Asymmetric);
        }
        if MgmCommand::contains_command(&SymOps::get_authorized_commands(authkey), &MgmCommandType::Generate) {
            types.push(MgmObjectType::Symmetric);
        }
        if MgmCommand::contains_command(&WrapOps::get_authorized_commands(authkey), &MgmCommandType::Generate) {
            types.push(MgmObjectType::Wrap);
        }
        if MgmCommand::contains_command(&JavaOps::get_authorized_commands(authkey), &MgmCommandType::Generate) {
            types.push(MgmObjectType::Java);
        }
        types
    }


    pub fn get_importable_types(authkey: &ObjectDescriptor) -> Vec<MgmObjectType> {
        let mut types = Vec::new();
        if MgmCommand::contains_command(&AsymOps::get_authorized_commands(authkey), &MgmCommandType::Import) {
            types.push(MgmObjectType::Asymmetric);
        }
        if MgmCommand::contains_command(&SymOps::get_authorized_commands(authkey), &MgmCommandType::Import) {
            types.push(MgmObjectType::Symmetric);
        }
        if MgmCommand::contains_command(&WrapOps::get_authorized_commands(authkey), &MgmCommandType::Import) {
            types.push(MgmObjectType::Wrap);
        }
        if MgmCommand::contains_command(&JavaOps::get_authorized_commands(authkey), &MgmCommandType::Import) {
            types.push(MgmObjectType::Java);
        }
        types
    }

    pub fn get_key_operation_types() -> Vec<MgmObjectType> {
        vec![
            MgmObjectType::Asymmetric,
            MgmObjectType::Symmetric,
            MgmObjectType::Wrap,
            MgmObjectType::Authentication,
        ]
    }

    pub fn get_special_case_types() -> Vec<MgmObjectType> {
        vec![
            MgmObjectType::Java,
            MgmObjectType::Ksp,
        ]
    }

}