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
use crate::common::types::NewObjectSpec;
use crate::common::error::MgmError;
use crate::common::algorithms::MgmAlgorithm;
use crate::common::types::{MgmCommand, MgmCommandType};
use crate::common::util::{get_object_descriptors, get_delegated_capabilities, get_authorized_commands};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserType {
    #[default]
    KeyUser,
    KeyAdmin,
    Auditor,
    CustomUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthenticationType {
    #[default]
    PasswordDerived,
    Ecp256,
}

pub struct AuthenticationOperations;

impl YubihsmOperations for AuthenticationOperations {

    fn context(&self) -> &'static str {
        AuthenticationOperations::AUTH_CONTEXT
    }

    fn get_authorized_commands(&self, authkey: &ObjectDescriptor) -> Vec<MgmCommand> {
        get_authorized_commands(authkey, &Self::COMMANDS)
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

    pub const AUTH_CONTEXT: &'static str = "auth";

    const COMMANDS: [MgmCommand; 8] = [
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
            label: "Setup keys user",
            description: "Can only use (a)symmetric keys and wrap keys stored on the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::SetupAdmin,
            label: "Setup keys admin",
            description: "Can only manage (a)symmetric keys and wrap keys stored on the YubiHSM",
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
            command: MgmCommandType::SetupCustomUser,
            label: "Setup custom user",
            description: "Can have all capabilities of the current user",
            required_capabilities: &[ObjectCapability::PutAuthenticationKey],
            require_all_capabilities: false,
        },
        MgmCommand::EXIT_COMMAND,
    ];

    pub const KEY_USER_CAPABILITIES: [ObjectCapability; 15] = [
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
        ObjectCapability::ExportWrapped,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const KEY_ADMIN_CAPABILITIES: [ObjectCapability; 14] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::PutAsymmetricKey,
        ObjectCapability::DeleteAsymmetricKey,
        ObjectCapability::PutOpaque,
        ObjectCapability::DeleteOpaque,
        ObjectCapability::GenerateSymmetricKey,
        ObjectCapability::PutSymmetricKey,
        ObjectCapability::DeleteSymmetricKey,
        ObjectCapability::GenerateWrapKey,
        ObjectCapability::PutWrapKey,
        ObjectCapability::PutPublicWrapKey,
        ObjectCapability::DeleteWrapKey,
        ObjectCapability::DeletePublicWrapKey,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub const AUDITOR_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::GetLogEntries,
        ObjectCapability::ExportableUnderWrap,
    ];

    /// Return the capabilities that are applicable to a user of the given type, based on the authentication key's
    /// delegated capabilities. For non-CustomUser types, this is the intersection of the auth key's delegated
    /// capabilities and the default capabilities for that user type. For CustomUser, this is just whatever
    /// capabilities the auth key has delegated (no filtering).
    pub fn get_applicable_capabilities(authkey: &ObjectDescriptor, user_type: UserType) -> Vec<ObjectCapability> {
        let auth_delegated = get_delegated_capabilities(authkey);
        let mut caps = match user_type {
            UserType::KeyUser => Self::KEY_USER_CAPABILITIES.to_vec(),
            UserType::KeyAdmin => Self::KEY_ADMIN_CAPABILITIES.to_vec(),
            UserType::Auditor => Self::AUDITOR_CAPABILITIES.to_vec(),
            UserType::CustomUser => get_delegated_capabilities(authkey),
        };

        if user_type != UserType::CustomUser {
            caps.retain(|c| auth_delegated.contains(c));
        }
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authkey_desc(
        caps: Vec<ObjectCapability>,
        delegated: Option<Vec<ObjectCapability>>,
    ) -> ObjectDescriptor {
        let mut desc = ObjectDescriptor::new();
        desc.id = 1;
        desc.object_type = ObjectType::AuthenticationKey;
        desc.capabilities = caps;
        desc.delegated_capabilities = delegated;
        desc
    }

    // ══════════════════════════════════════════════
    //  get_applicable_capabilities
    // ══════════════════════════════════════════════

    #[test]
    fn test_applicable_caps_key_user_full_delegated() {
        // Auth key that delegates all KEY_USER caps
        let delegated = AuthenticationOperations::KEY_USER_CAPABILITIES.to_vec();
        let authkey = make_authkey_desc(vec![], Some(delegated.clone()));
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::KeyUser);
        assert_eq!(caps.len(), AuthenticationOperations::KEY_USER_CAPABILITIES.len());
        assert!(caps.iter().all(|c| AuthenticationOperations::KEY_USER_CAPABILITIES.contains(c)));
    }

    #[test]
    fn test_applicable_caps_key_user_partial_delegated() {
        // Auth key only delegates 2 of the 15 KEY_USER caps
        let delegated = vec![ObjectCapability::SignPkcs, ObjectCapability::SignPss];
        let authkey = make_authkey_desc(vec![], Some(delegated.clone()));
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::KeyUser);
        // Only the 2 that overlap with KEY_USER_CAPABILITIES
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&ObjectCapability::SignPkcs));
        assert!(caps.contains(&ObjectCapability::SignPss));
    }

    #[test]
    fn test_applicable_caps_key_admin() {
        let delegated = AuthenticationOperations::KEY_ADMIN_CAPABILITIES.to_vec();
        let authkey = make_authkey_desc(vec![], Some(delegated));
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::KeyAdmin);
        assert_eq!(caps.len(), AuthenticationOperations::KEY_ADMIN_CAPABILITIES.len());
        assert!(caps.iter().all(|c| AuthenticationOperations::KEY_ADMIN_CAPABILITIES.contains(c)));
    }

    #[test]
    fn test_applicable_caps_auditor() {
        let delegated = AuthenticationOperations::AUDITOR_CAPABILITIES.to_vec();
        let authkey = make_authkey_desc(vec![], Some(delegated));
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::Auditor);
        assert_eq!(caps.len(), AuthenticationOperations::AUDITOR_CAPABILITIES.len());
        assert!(caps.iter().all(|c| AuthenticationOperations::AUDITOR_CAPABILITIES.contains(c)));
    }

    #[test]
    fn test_applicable_caps_custom_user_returns_delegated() {
        // CustomUser returns whatever the auth key has delegated — no filtering
        let delegated = vec![
            ObjectCapability::SignPkcs,
            ObjectCapability::GenerateAsymmetricKey,
            ObjectCapability::GetLogEntries,
        ];
        let authkey = make_authkey_desc(vec![], Some(delegated.clone()));
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::CustomUser);
        assert_eq!(caps, delegated);
    }

    #[test]
    fn test_applicable_caps_no_delegated() {
        // Auth key with no delegated capabilities → empty for any role
        let authkey = make_authkey_desc(vec![], None);
        let caps = AuthenticationOperations::get_applicable_capabilities(&authkey, UserType::KeyUser);
        assert!(caps.is_empty());
    }

    // ══════════════════════════════════════════════
    //  Enum defaults
    // ══════════════════════════════════════════════

    #[test]
    fn test_user_type_default() {
        assert_eq!(UserType::default(), UserType::KeyUser);
    }

    #[test]
    fn test_authentication_type_default() {
        assert_eq!(AuthenticationType::default(), AuthenticationType::PasswordDerived);
    }
}