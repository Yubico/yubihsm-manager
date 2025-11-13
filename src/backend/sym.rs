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
use crate::backend::common::get_authorized_commands;
use crate::backend::common::get_op_keys;
use crate::backend::common::get_descriptors_from_handlers;
use crate::backend::object_ops::{Deletable, Generatable, Importable, Obtainable};
use crate::backend::types::{CommandSpec, ImportObjectSpec, ObjectSpec, YhCommand};
use crate::backend::error::MgmError;

pub struct SymOps;

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AesMode {
    #[default]
    Ecb,
    Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum EncryptionMode {
    #[default]
    Encrypt,
    Decrypt,
}

pub struct AesOperationSpec {
    pub operation_key: ObjectDescriptor,
    pub aes_mode: AesMode,
    pub enc_mode: EncryptionMode,
    pub iv: Vec<u8>,
    pub data: Vec<u8>,
}

impl Obtainable for SymOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let keys = session.list_objects_with_filter(
            0,
            ObjectType::SymmetricKey,
            "",
            ObjectAlgorithm::ANY,
            &Vec::new())?;
        get_descriptors_from_handlers(session, &keys)
    }

    fn get_object_algorithms() -> Vec<MgmAlgorithm> {
        MgmAlgorithm::AES_KEY_ALGORITHMS.to_vec()
    }

    fn get_object_capabilities(_: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        Self::AES_KEY_CAPABILITIES.to_vec()
    }
}

impl Deletable for SymOps {
    fn delete(&self, session: &Session, object_id: u16, _: ObjectType) -> Result<(), MgmError> {
        session.delete_object(object_id, ObjectType::SymmetricKey)?;
        Ok(())
    }
}

impl Generatable for SymOps {
    fn generate(&self, session: &Session, spec: &ObjectSpec) -> Result<u16, MgmError> {
        Ok(session
            .generate_aes_key(
                spec.id,
                &spec.label,
                &spec.capabilities,
                &spec.domains,
                spec.algorithm)?)
    }
}

impl Importable for SymOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        Ok(session
            .import_aes_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                spec.object.algorithm,
                &spec.data[0])?)
    }
}

impl SymOps {

    const AES_KEY_CAPABILITIES: [ObjectCapability; 5] = [
        ObjectCapability::EncryptCbc,
        ObjectCapability::DecryptCbc,
        ObjectCapability::EncryptEcb,
        ObjectCapability::DecryptEcb,
        ObjectCapability::ExportableUnderWrap];

    const SYM_COMMANDS: [CommandSpec;9] = [
        CommandSpec {
            command: YhCommand::List,
            label: "List",
            description: "List all asymmetric keys and X509 certificates stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        CommandSpec {
            command: YhCommand::GetKeyProperties,
            label: "Get Object Properties",
            description: "Get properties of an asymmetric key or X509 certificate stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Generate,
            label: "Generate",
            description: "Generate a new asymmetric key inside the YubiHSM",
            required_capabilities: &[ObjectCapability::GenerateSymmetricKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Import,
            label: "Import",
            description: "Import an asymmetric key or X509 certificate into the YubiHSM",
            required_capabilities: &[ObjectCapability::PutSymmetricKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Delete,
            label: "Delete",
            description: "Delete an asymmetric key or X509 certificate from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteSymmetricKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Encrypt,
            label: "Encrypt",
            description: "Encrypt data using an AES key stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::EncryptEcb, ObjectCapability::EncryptCbc],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Decrypt,
            label: "Decrypt",
            description: "Decrypt data using an AES key stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::DecryptEcb, ObjectCapability::DecryptCbc],
            require_all_capabilities: false,
        },
        CommandSpec::RETURN_COMMAND,
        CommandSpec::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<CommandSpec> {
        get_authorized_commands(authkey, &Self::SYM_COMMANDS)
    }

    pub fn is_aes_algorithm(algorithm: &ObjectAlgorithm) -> bool {
        MgmAlgorithm::AES_KEY_ALGORITHMS.iter().any(|a| a.algorithm() == *algorithm)
    }

    pub fn get_symkey_algorithm_from_keylen(keylen: usize) -> Result<ObjectAlgorithm, MgmError> {
        match keylen {
            16 => Ok(ObjectAlgorithm::Aes128),
            24 => Ok(ObjectAlgorithm::Aes192),
            32 => Ok(ObjectAlgorithm::Aes256),
            _ => Err(MgmError::Error(format!("Unsupported key length {}", keylen))),
        }
    }

    pub fn get_operation_keys(session:&Session, authkey: &ObjectDescriptor, enc_mode: EncryptionMode, aes_mode: AesMode) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let caps = match enc_mode {
            EncryptionMode::Encrypt => match aes_mode {
                AesMode::Ecb => [ObjectCapability::EncryptEcb],
                AesMode::Cbc => [ObjectCapability::EncryptCbc],
            },
            EncryptionMode::Decrypt => match aes_mode {
                AesMode::Ecb => [ObjectCapability::DecryptEcb],
                AesMode::Cbc => [ObjectCapability::DecryptCbc],
            },
        };
        let keys = get_op_keys(
            session,
            authkey,
            &caps,
            ObjectType::SymmetricKey,
            Some(&MgmAlgorithm::extract_algorithms(&MgmAlgorithm::AES_KEY_ALGORITHMS))
        )?;
        Ok(keys)
    }

    pub fn operate(session:&Session, op_spec: AesOperationSpec) -> Result<Vec<u8>, MgmError> {
        let out_data = match op_spec.enc_mode {
            EncryptionMode::Encrypt => {
                match op_spec.aes_mode {
                    AesMode::Ecb => session.encrypt_aes_ecb(op_spec.operation_key.id, &op_spec.data)?,
                    AesMode::Cbc => session.encrypt_aes_cbc(op_spec.operation_key.id, &op_spec.iv, &op_spec.data)?
                }
            },
            EncryptionMode::Decrypt => {
                match op_spec.aes_mode {
                    AesMode::Ecb => session.decrypt_aes_ecb(op_spec.operation_key.id, &op_spec.data)?,
                    AesMode::Cbc => session.decrypt_aes_cbc(op_spec.operation_key.id, &op_spec.iv, &op_spec.data)?
                }
            }
        };
        Ok(out_data)
    }
}
