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

use yubihsmrs::Session;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};
use crate::traits::backend_traits::YubihsmOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::common::contains_all;
use crate::hsm_operations::wrap::{WrapKeyShares, WrapOperations};
use crate::hsm_operations::auth::AuthenticationOperations;
use crate::hsm_operations::types::NewObjectSpec;

pub struct KspOperations;

impl KspOperations {
    const KSP_WRAPKEY_LEN: usize = 32;

    const REQUIRED_CAPABILITIES: [ObjectCapability; 4] = [
        ObjectCapability::GetPseudoRandom,
        ObjectCapability::PutWrapKey,
        ObjectCapability::PutAuthenticationKey,
        ObjectCapability::ExportWrapped];

    const RSA_DECRYPT_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep];

    const WRAPKEY_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped];

    const WRAPKEY_DELEGATED: [ObjectCapability;10] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetLogEntries,
    ];

    const APP_AUTHKEY_CAPABILITIES: [ObjectCapability; 10] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ImportWrapped,
        ObjectCapability::ExportWrapped,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetOption,
    ];

    const APP_AUTHKEY_DELEGATED: [ObjectCapability; 8] = [
        ObjectCapability::GenerateAsymmetricKey,
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::SignEcdsa,
        ObjectCapability::SignEddsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::GetOption,
    ];

    const AUDIT_AUTHKEY_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::GetLogEntries,
        ObjectCapability::ExportableUnderWrap,
    ];

    pub fn check_privileges(authkey: &ObjectDescriptor) -> Result<(), MgmError> {
        if !contains_all(authkey.capabilities.as_slice(), &Self::REQUIRED_CAPABILITIES) {
            return Err(MgmError::Error("Current user does not have the necessary permissions to setup the YubiHSM for KSP use case".to_string()))
        }
        Ok(())
    }

    pub fn import_ksp_wrapkey(session: &Session, id: u16, domains: &[ObjectDomain], rsa_decrypt: bool, shares: u8, threshold: u8) -> Result<(u16, WrapKeyShares), MgmError> {
        let wrapkey = session.get_random(Self::KSP_WRAPKEY_LEN)?;

        let mut new_key = NewObjectSpec::new(
            id,
            ObjectType::WrapKey,
            "KSP Wrap Key".to_string(),
            ObjectAlgorithm::Aes256CcmWrap,
            domains.to_vec(),
            Self::WRAPKEY_CAPABILITIES.to_vec(),
            Self::expand_capabilities(&Self::WRAPKEY_DELEGATED, rsa_decrypt),
            vec![wrapkey],
        );

        new_key.id = WrapOperations.import(session, &new_key)?;

        let wrapkey_shares = WrapOperations::split_wrap_key(&new_key, threshold, shares)?;

        Ok((new_key.id, wrapkey_shares))
    }

    pub fn import_app_authkey(
        session: &Session,
        id: u16,
        domains: &[ObjectDomain],
        rsa_decrypt: bool,
        password: String) -> Result<ObjectDescriptor, MgmError> {

        let mut new_key = NewObjectSpec::new(
            id,
            ObjectType::AuthenticationKey,
            "Application auth key".to_string(),
            ObjectAlgorithm::Aes128YubicoAuthentication,
            domains.to_vec(),
            Self::expand_capabilities(&Self::APP_AUTHKEY_CAPABILITIES, rsa_decrypt),
            Self::expand_capabilities(&Self::APP_AUTHKEY_DELEGATED, rsa_decrypt),
            vec![password.into_bytes()],
        );

        new_key.id = AuthenticationOperations.import(session, &new_key)?;

        Ok(new_key.into())
    }

    pub fn import_audit_authkey(session: &Session, id: u16, domains: &[ObjectDomain], password: String) -> Result<ObjectDescriptor, MgmError> {

        let mut new_key = NewObjectSpec::new(
            id,
            ObjectType::AuthenticationKey,
            "Audit auth key".to_string(),
            ObjectAlgorithm::Aes128YubicoAuthentication,
            domains.to_vec(),
            Self::AUDIT_AUTHKEY_CAPABILITIES.to_vec(),
            vec![],
            vec![password.into_bytes()],
        );

        new_key.id = AuthenticationOperations.import(session, &new_key)?;

        Ok(new_key.into())
    }

    fn expand_capabilities(capabilities: &[ObjectCapability], expand: bool) -> Vec<ObjectCapability> {
        let mut caps = capabilities.to_vec();
        if expand {
            caps.extend_from_slice(&Self::RSA_DECRYPT_CAPABILITIES);
        }
        caps
    }
}





