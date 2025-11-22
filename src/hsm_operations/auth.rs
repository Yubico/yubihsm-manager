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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::hsm_operations::types::NewObjectSpec;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::types::{MgmCommand, MgmCommandType};
use crate::hsm_operations::common::{get_object_descriptors, get_delegated_capabilities};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserType {
    #[default]
    AsymUser,
    AsymAdmin,
    Auditor,
    BackupAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationType {
    #[default]
    PasswordDerived,
    Ecp256,
}

pub struct AuthenticationOperations;

impl YubihsmOperations for AuthenticationOperations {

    fn get_commands(&self) -> Vec<MgmCommand> {
        [
            MgmCommand {
                command: MgmCommandType::List,
                label: "List",
                description: "List all authentication keys stored in the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false
            },
            MgmCommand {
                command: MgmCommandType::GetKeyProperties,
                label: "Get object properties",
                description: "Get properties of an authentication key stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Delete,
                label: "Delete",
                description: "Delete an authentication key from the YubiHSM",
                required_capabilities: &[ObjectCapability::DeleteAuthenticationKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::SetupUser,
                label: "Setup (a)symmetric keys user",
                description: "Can only use (a)symmetric keys stored on the YubiHSM",
                required_capabilities: &[ObjectCapability::PutAuthenticationKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::SetupAdmin,
                label: "Setup (a)symmetric keys admin",
                description: "Can only manage (a)symmetric keys stored on the YubiHSM",
                required_capabilities: &[ObjectCapability::PutAuthenticationKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::SetupAuditor,
                label: "Setup auditor user",
                description: "Can only perform audit functions on the YubiHSM",
                required_capabilities: &[ObjectCapability::PutAuthenticationKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::SetupBackupAdmin,
                label: "Setup custom user",
                description: "Can have all capabilities of the current user",
                required_capabilities: &[ObjectCapability::PutAuthenticationKey],
                require_all_capabilities: false,
            },
            MgmCommand::EXIT_COMMAND,
        ].to_vec()
    }

    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let keys = session.list_objects_with_filter(
            0,
            ObjectType::AuthenticationKey,
            "",
            ObjectAlgorithm::ANY,
            &Vec::new())?;
        get_object_descriptors(session, &keys)
    }

    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm> {
        unimplemented!()
    }

    fn get_object_capabilities(
        &self,
        _object_type: Option<ObjectType>,
        _object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        unimplemented!()
    }

    fn get_applicable_capabilities(&self, _authkey: &ObjectDescriptor, _object_type: Option<ObjectType>, _object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        unimplemented!()
    }

    fn generate(&self, _session: &Session, _spec: &NewObjectSpec) -> Result<u16, MgmError> {
        unimplemented!()
    }

    fn import(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        let id = match spec.algorithm {
            ObjectAlgorithm::Aes128YubicoAuthentication => {
                session.import_authentication_key(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    &spec.delegated_capabilities,
                    &spec.data[0])?
            },
            ObjectAlgorithm::Ecp256YubicoAuthentication => {
                session.import_authentication_publickey(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    &spec.delegated_capabilities,
                    &spec.data[0])?
            }
            _ => {
                return Err(MgmError::InvalidInput(
                    format!("Unsupported algorithm for authentication key: {}", spec.algorithm)
                ));
            }
        };
        Ok(id)
    }
}

impl AuthenticationOperations {
    pub const KEY_USER_CAPABILITIES: [ObjectCapability; 13] = [
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa,
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::SignAttestationCertificate,
        ObjectCapability::EncryptEcb,
        ObjectCapability::EncryptCbc,
        ObjectCapability::DecryptEcb,
        ObjectCapability::DecryptCbc,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const KEY_ADMIN_CAPABILITIES: [ObjectCapability; 9] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::PutAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey,
        ObjectCapability::PutOpaque,
        ObjectCapability::DeleteOpaque,
        ObjectCapability::GenerateSymmetricKey,
        ObjectCapability::PutSymmetricKey,
        ObjectCapability::DeleteSymmetricKey,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const AUDITOR_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::GetLogEntries,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub fn get_applicable_capabilities(authkey: &ObjectDescriptor, user_type: UserType) -> Vec<ObjectCapability> {
        let auth_delegated = get_delegated_capabilities(authkey);
        let mut caps = match user_type {
            UserType::AsymUser => Self::KEY_USER_CAPABILITIES.to_vec(),
            UserType::AsymAdmin => Self::KEY_ADMIN_CAPABILITIES.to_vec(),
            UserType::Auditor => Self::AUDITOR_CAPABILITIES.to_vec(),
            UserType::BackupAdmin => get_delegated_capabilities(authkey),
        };

        if user_type != UserType::BackupAdmin {
            caps.retain(|c| auth_delegated.contains(c));
        }
        caps
    }
}