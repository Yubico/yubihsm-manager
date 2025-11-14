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
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::object_ops::Importable;
use crate::backend::types::{ImportObjectSpec, CommandSpec, YhCommand};
use crate::backend::common::{get_descriptors_from_handlers, get_authorized_commands};
use crate::backend::object_ops::{Deletable, Obtainable};
use crate::backend::error::MgmError;

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

pub struct AuthOps;

impl Obtainable for AuthOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let keys = session.list_objects_with_filter(
            0,
            ObjectType::AuthenticationKey,
            "",
            ObjectAlgorithm::ANY,
            &Vec::new())?;
        get_descriptors_from_handlers(session, &keys)
    }

    fn get_object_algorithms() -> Vec<MgmAlgorithm> {
        unimplemented!()
    }

    fn get_object_capabilities(_: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        unimplemented!()
    }
}

impl Deletable for AuthOps {
    // fn delete(&self, session: &Session, object_id: u16, _: ObjectType) -> Result<(), MgmError> {
    //     session.delete_object(object_id, ObjectType::AuthenticationKey)?;
    //     Ok(())
    // }
}

impl Importable for AuthOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        let id = match spec.object.algorithm {
            ObjectAlgorithm::Aes128YubicoAuthentication => {
                session.import_authentication_key(
                    spec.object.id,
                    &spec.object.label,
                    &spec.object.domains,
                    &spec.object.capabilities,
                    &spec.object.delegated_capabilities,
                    &spec.data[0])?
            },
            ObjectAlgorithm::Ecp256YubicoAuthentication => {
                session.import_authentication_publickey(
                    spec.object.id,
                    &spec.object.label,
                    &spec.object.domains,
                    &spec.object.capabilities,
                    &spec.object.delegated_capabilities,
                    &spec.data[0])?
            }
            _ => {
                return Err(MgmError::InvalidInput(
                    format!("Unsupported algorithm for authentication key: {}", spec.object.algorithm)
                ));
            }
        };
        Ok(id)
    }
}

impl AuthOps {
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

    const AUTH_COMMANDS: [CommandSpec;9] = [
        CommandSpec {
            command: YhCommand::List,
            label: "List",
            description: "List all authentication keys stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        CommandSpec {
            command: YhCommand::GetKeyProperties,
            label: "Get object properties",
            description: "Get properties of an authentication key stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Delete,
            label: "Delete",
            description: "Delete an authentication key from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteAuthenticationKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::SetupUser,
            label: "Setup (a)symmetric keys user",
            description: "Can only use (a)symmetric keys stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::SetupAdmin,
            label: "Setup (a)symmetric keys admin",
            description: "Can only manage (a)symmetric keys stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::SetupAuditor,
            label: "Setup auditor user",
            description: "Can only perform audit functions on the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::SetupBackupAdmin,
            label: "Setup custom user",
            description: "Can have all capabilities of the current user",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        CommandSpec::RETURN_COMMAND,
        CommandSpec::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<CommandSpec> {
        get_authorized_commands(authkey, &Self::AUTH_COMMANDS)
    }
}