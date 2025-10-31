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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::backend::common::get_delegated_capabilities;
use crate::error::MgmError;

pub const ASYM_USER_CAPABILITIES: [ObjectCapability; 13] = [
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

pub const ASYM_ADMIN_CAPABILITIES: [ObjectCapability; 9] = [
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

pub struct AuthenticationKey {
    pub descriptor: ObjectDescriptor,
    pub auth_type: AuthenticationType,
    pub key: Vec<u8>,
}

pub fn get_auth_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    Ok(session.list_objects_with_filter(
        0,
        ObjectType::AuthenticationKey,
        "",
        ObjectAlgorithm::ANY,
        &Vec::new())?)
}

pub fn import_authkey(session:&Session, new_key:&AuthenticationKey) -> Result<u16, MgmError> {
    let id = match new_key.auth_type {
        AuthenticationType::PasswordDerived => {
                session.import_authentication_key(
                    new_key.descriptor.id,
                    &new_key.descriptor.label,
                    &new_key.descriptor.domains,
                    &new_key.descriptor.capabilities,
                    get_delegated_capabilities(&new_key.descriptor).as_slice(),
                    new_key.key.as_slice())?
        },
        AuthenticationType::Ecp256 => {
                session.import_authentication_publickey(
                    new_key.descriptor.id,
                    &new_key.descriptor.label,
                    &new_key.descriptor.domains,
                    &new_key.descriptor.capabilities,
                    get_delegated_capabilities(&new_key.descriptor).as_slice(),
                    new_key.key.as_slice())?
        }
    };
    Ok(id)
}