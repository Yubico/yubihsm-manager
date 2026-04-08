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
use strum_macros::EnumIter;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::traits::command_traits::Command;
use crate::common::algorithms::MgmAlgorithm;
use crate::common::error::MgmError;
use crate::common::types::{NewObjectSpec, SelectionItem, EXIT_LABEL};
use crate::common::util::get_object_descriptors;

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum MainCommand {
    List,
    Search,
    Delete,
    Generate,
    Import,
    GotoAsym,
    GotoSym,
    GotoWrap,
    GotoAuth,
    GotoSpecialOps,
    GotoDevice,
    Exit,
}

impl Command for MainCommand {

    fn label(&self) -> &'static str {
        match self {
            Self::List => "List",
            Self::Search => "Search objects",
            Self::Delete => "Delete",
            Self::Generate => "Generate",
            Self::Import => "Import",
            Self::GotoAsym => "[Asymmetric Key operations]",
            Self::GotoSym => "[Symmetric Key operations]",
            Self::GotoWrap => "[Wrap Key operations]",
            Self::GotoAuth => "[Authentication Key operations]",
            Self::GotoSpecialOps => "[Special operations]",
            Self::GotoDevice => "[Device operations]",
            Self::Exit => EXIT_LABEL,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::List => "List all objects stored on the YubiHSM",
            Self::Search => "Search for objects stored on the YubiHSM by ID, type or label",
            Self::Delete => "Delete an object from the YubiHSM",
            Self::Generate => "Generate a new key inside the YubiHSM",
            Self::Import => "Import an object into the YubiHSM",
            Self::GotoAsym => "Manage and use asymmetric keys stored on the YubiHSM",
            Self::GotoSym => "Manage and use symmetric keys stored on the YubiHSM. Requires firmware version 2.3.1 or higher",
            Self::GotoWrap => "Manage and use wrap keys stored on the YubiHSM",
            Self::GotoAuth => "Manage authentication keys stored on the YubiHSM",
            Self::GotoSpecialOps => "",
            Self::GotoDevice => "Get pseudo random number, backup, restore or reset device",
            Self::Exit => "",
        }
    }

    fn required_capabilities(&self) -> &'static [ObjectCapability] {
        match self {
            Self::List | Self::Search | Self::Exit => &[],
            Self::Delete => &[
                ObjectCapability::DeleteAsymmetricKey,
                ObjectCapability::DeleteOpaque,
                ObjectCapability::DeleteSymmetricKey,
                ObjectCapability::DeleteWrapKey,
                ObjectCapability::DeletePublicWrapKey,
                ObjectCapability::DeleteAuthenticationKey],
            Self::Generate => &[
                ObjectCapability::GenerateAsymmetricKey,
                ObjectCapability::GenerateSymmetricKey,
                ObjectCapability::GenerateWrapKey],
            Self::Import => &[
                ObjectCapability::PutAsymmetricKey,
                ObjectCapability::PutOpaque,
                ObjectCapability::PutSymmetricKey,
                ObjectCapability::PutWrapKey,
                ObjectCapability::PutPublicWrapKey,
                ObjectCapability::ImportWrapped],
            Self::GotoAsym | Self::GotoSym | Self::GotoWrap | Self::GotoAuth | Self::GotoSpecialOps => &[],
            Self::GotoDevice => &[
                ObjectCapability::GetPseudoRandom,
                ObjectCapability::ExportWrapped,
                ObjectCapability::ImportWrapped],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter)]
pub enum SpecialOpCommand {
    SunPkcs11,
    Ksp,
}

impl Command for SpecialOpCommand {
    fn label(&self) -> &'static str {
        match self {
            Self::SunPkcs11 => "SunPKCS11",
            Self::Ksp => "KSP setup",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::SunPkcs11 => "Manage asymmetric keys with properties compatible with SunPKCS11 provider in Java",
            Self::Ksp => "Guided setup of the YubiHSM for Windows KSP/CNG provider",
        }
    }

    fn required_capabilities(&self) -> &'static [ObjectCapability] {
        &[]
    }
}

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

#[derive(Debug, Clone, PartialEq,  Eq)]
pub enum ImportableType {
    ObjectType(ObjectType),
    Wrapped,
}

pub struct MainOperations;

impl YubihsmOperations for MainOperations {

    fn context(&self) -> &'static str {
        MainOperations::MAIN_CONTEXT
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

    pub fn get_filtered_objects(session: &Session, filter: FilterType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let objects =
        match filter {
            FilterType::Id(id) => {
                let handles = session.list_objects_with_filter(id, ObjectType::Any, "", ObjectAlgorithm::ANY, &[])?;
                get_object_descriptors(session, &handles)?
            },
            FilterType::Type(types) => {
                let mut objects = Self.get_all_objects(session)?;
                objects.retain(|obj| types.contains(obj.object_type()));
                if types.contains(&ObjectType::Opaque) {
                    objects.retain(|obj| obj.object_type() != &ObjectType::Opaque || obj.algorithm() == &ObjectAlgorithm::OpaqueX509Certificate);
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
                match obj.object_type() {
                    ObjectType::AsymmetricKey => authkey.capabilities().contains(&ObjectCapability::DeleteAsymmetricKey),
                    ObjectType::Opaque => authkey.capabilities().contains(&ObjectCapability::DeleteOpaque),
                    ObjectType::SymmetricKey => authkey.capabilities().contains(&ObjectCapability::DeleteSymmetricKey),
                    ObjectType::WrapKey => authkey.capabilities().contains(&ObjectCapability::DeleteWrapKey),
                    ObjectType::PublicWrapKey => authkey.capabilities().contains(&ObjectCapability::DeletePublicWrapKey),
                    ObjectType::AuthenticationKey => authkey.capabilities().contains(&ObjectCapability::DeleteAuthenticationKey),
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
        if authkey.capabilities().contains(&ObjectCapability::GenerateAsymmetricKey) {
            types.push(SelectionItem {
                value: ObjectType::AsymmetricKey,
                label: "Asymmetric private key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities().contains(&ObjectCapability::GenerateSymmetricKey) {
            types.push(SelectionItem {
                value: ObjectType::SymmetricKey,
                label: "Symmetric key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities().contains(&ObjectCapability::GenerateWrapKey) {
            types.push(SelectionItem {
                value: ObjectType::WrapKey,
                label: "Wrap key".to_string(),
                description: String::new()
            });
        }
        types
    }

    pub fn get_importable_types(authkey: &ObjectDescriptor) -> Vec<SelectionItem<ImportableType>> {
        let mut types = Vec::new();
        if authkey.capabilities().contains(&ObjectCapability::PutAsymmetricKey) ||
            authkey.capabilities().contains(&ObjectCapability::PutOpaque) {
            types.push(SelectionItem {
                value: ImportableType::ObjectType(ObjectType::AsymmetricKey),
                label: "Asymmetric object".to_string(),
                description: "Asymmetric private key or X509Certificate".to_string()
            });
        }
        if authkey.capabilities().contains(&ObjectCapability::PutSymmetricKey) {
            types.push(SelectionItem {
                value: ImportableType::ObjectType(ObjectType::SymmetricKey),
                label: "Symmetric key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities().contains(&ObjectCapability::PutWrapKey) ||
            authkey.capabilities().contains(&ObjectCapability::PutPublicWrapKey) {
            types.push(SelectionItem {
                value: ImportableType::ObjectType(ObjectType::WrapKey),
                label: "Wrap key".to_string(),
                description: String::new()
            });
        }
        if authkey.capabilities().contains(&ObjectCapability::ImportWrapped) {
            types.push(SelectionItem {
                value: ImportableType::Wrapped,
                label: "Wrapped Object".to_string(),
                description: String::new()
            });
        }
        types
    }

    pub fn get_special_ops() -> Vec<SelectionItem<SpecialOpCommand>> {
        vec![
            SelectionItem {
                value: SpecialOpCommand::SunPkcs11,
                label: SpecialOpCommand::SunPkcs11.label().to_string(),
                description: SpecialOpCommand::SunPkcs11.description().to_string()
            },
             SelectionItem {
                value: SpecialOpCommand::Ksp,
                label: SpecialOpCommand::Ksp.label().to_string(),
                description: SpecialOpCommand::Ksp.description().to_string()
            },
        ]
    }
}