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
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::types::NewObjectSpec;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::types::{MgmCommand, MgmCommandType};
use crate::hsm_operations::common::get_object_descriptors;

#[derive(Debug, Clone, PartialEq,  Eq)]
pub enum FilterType {
    Id(u16),
    Label(String),
    Type(Vec<MgmObjectType>),
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
            MgmObjectType::Asymmetric => write!(f, "Asymmetric key operations"),
            MgmObjectType::Symmetric => write!(f, "Symmetric key operations"),
            MgmObjectType::Certificate => write!(f, "X509Certificate operations"),
            MgmObjectType::Wrap => write!(f, "Wrap key operations"),
            MgmObjectType::Authentication => write!(f, "Authentication key operations"),
            MgmObjectType::Java => write!(f, "Special case: SunPKCS11 compatible key operations"),
            MgmObjectType::Ksp => write!(f, "Special case: KSP setup"),

        }
    }
}

impl From<MgmObjectType> for ObjectType {
    fn from(mgm_type: MgmObjectType) -> Self {
        match mgm_type {
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

pub struct MainOperations;

impl YubihsmOperations for MainOperations {
    fn get_commands(&self) -> Vec<MgmCommand> {
        [
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
        ].to_vec()
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

    pub fn get_filtered_objects(session: &Session, filter: FilterType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let objects =
        match filter {
            FilterType::Id(id) => {
                let handles = session.list_objects_with_filter(id, ObjectType::Any, "", ObjectAlgorithm::ANY, &[])?;
                get_object_descriptors(session, &handles)?
            },
            FilterType::Type(types) => {
                let mut objects = Self.get_all_objects(session)?;
                objects.retain(|obj| types.iter().any(|t| <MgmObjectType as Into<ObjectType>>::into(t.to_owned()) == obj.object_type));
                if types.contains(&MgmObjectType::Certificate) {
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
                    ObjectType::PublicWrapKey => authkey.capabilities.contains(&ObjectCapability::DeleteWrapKey),
                    ObjectType::AuthenticationKey => authkey.capabilities.contains(&ObjectCapability::DeleteAuthenticationKey),
                    _ => false,
                }
            });
        Ok(objects)
    }

    pub fn get_search_by_types() -> Vec<MgmObjectType> {
        vec![
            MgmObjectType::Asymmetric,
            MgmObjectType::Symmetric,
            MgmObjectType::Certificate,
            MgmObjectType::Authentication,
            MgmObjectType::Wrap,
        ]
    }

    pub fn get_generatable_types(authkey: &ObjectDescriptor) -> Vec<MgmObjectType> {
        let mut types = Vec::new();
        if authkey.capabilities.contains(&ObjectCapability::GenerateAsymmetricKey) {
            types.push(MgmObjectType::Asymmetric);
        }
        if authkey.capabilities.contains(&ObjectCapability::GenerateSymmetricKey) {
            types.push(MgmObjectType::Symmetric);
        }
        if authkey.capabilities.contains(&ObjectCapability::GenerateWrapKey) {
            types.push(MgmObjectType::Wrap);
        }
        types
    }


    pub fn get_importable_types(authkey: &ObjectDescriptor) -> Vec<MgmObjectType> {
        let mut types = Vec::new();
        if authkey.capabilities.contains(&ObjectCapability::PutAsymmetricKey) {
            types.push(MgmObjectType::Asymmetric);
        }
        if authkey.capabilities.contains(&ObjectCapability::PutOpaque) {
            types.push(MgmObjectType::Certificate);
        }
        if authkey.capabilities.contains(&ObjectCapability::PutSymmetricKey) {
            types.push(MgmObjectType::Symmetric);
        }
        if authkey.capabilities.contains(&ObjectCapability::PutWrapKey) {
            types.push(MgmObjectType::Wrap);
        }
        if authkey.capabilities.contains(&ObjectCapability::PutAuthenticationKey) {
            types.push(MgmObjectType::Authentication);
        }
        types
    }

    pub fn get_key_operation_types() -> Vec<MgmObjectType> {
        vec![
            MgmObjectType::Asymmetric,
            MgmObjectType::Symmetric,
            MgmObjectType::Wrap,
            MgmObjectType::Authentication,
            MgmObjectType::Java,
            MgmObjectType::Ksp,
        ]
    }

}