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

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};
use yubihsmrs::Session;
use crate::backend::auth_utils::{AuthenticationKey, AuthenticationType, import_authkey};
use crate::backend::wrap_utils::{import_wrap_key, WrapKeyShares, split_wrap_key};
use crate::backend::common::contains_all;
use crate::error::MgmError;

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

pub struct KspAuthKeyInput {
    pub id: u16,
    pub password: String,
}

pub struct KspWrapKeyInput {
    pub id: u16,
    pub domains: Vec<ObjectDomain>,
    pub shares: u8,
    pub threshold: u8,
}

pub struct KspSetup {
    pub wrapkey_id: u16,
    pub wrapkey: WrapKeyShares,
    pub appkey_desc: ObjectDescriptor,
    pub auditkey_desc: Option<ObjectDescriptor>,
}

pub fn check_privileges(authkey: &ObjectDescriptor) -> Result<(), MgmError> {
    if !contains_all(authkey.capabilities.as_slice(), &REQUIRED_CAPABILITIES) {
        return Err(MgmError::Error("Current user does not have the necessary permissions to setup the YubiHSM for KSP use case".to_string()))
    }
    Ok(())
}

pub fn import_ksp_wrapkey(session: &Session, id: u16, domains: &Vec<ObjectDomain>, rsa_decrypt: bool, shares: u8, threshold: u8) -> Result<(u16, WrapKeyShares), MgmError> {
    let wrapkey = session.get_random(KSP_WRAPKEY_LEN)?;

    let mut desc = ObjectDescriptor::new();
    desc.id = id;
    desc.object_type = ObjectType::WrapKey;
    desc.label = "KSP Wrap Key".to_string();
    desc.algorithm = ObjectAlgorithm::Aes256CcmWrap;
    desc.domains = domains.clone();
    desc.capabilities = WRAPKEY_CAPABILITIES.to_vec();
    desc.delegated_capabilities = Some(get_capabilities(&WRAPKEY_DELEGATED, rsa_decrypt));
    desc.id = import_wrap_key(session, &desc, &wrapkey)?;

    let wrapkey_shares = split_wrap_key(
        &desc.clone(),
        threshold,
        shares,
        wrapkey.as_slice(),
    )?;

    Ok((desc.id, wrapkey_shares))
}

pub fn import_app_authkey(session: &Session, id: u16, domains: &Vec<ObjectDomain>, rsa_decrypt: bool, password: String) -> Result<ObjectDescriptor, MgmError> {
    let mut desc = ObjectDescriptor::new();
    desc.id = id;
    desc.object_type = ObjectType::AuthenticationKey;
    desc.label = "Application auth key".to_string();
    desc.domains = domains.clone();
    desc.capabilities = get_capabilities(&APP_AUTHKEY_CAPABILITIES, rsa_decrypt);
    desc.delegated_capabilities = Some(get_capabilities(&APP_AUTHKEY_DELEGATED, rsa_decrypt));
    let appkey = AuthenticationKey {
        descriptor: desc.clone(),
        auth_type: AuthenticationType::PasswordDerived,
        key: password.into_bytes(),
    };
    desc.id = import_authkey(session, &appkey)?;
    Ok(desc)
}

pub fn import_audit_authkey(session: &Session, id: u16, domains: &Vec<ObjectDomain>, password: String) -> Result<ObjectDescriptor, MgmError> {
    let mut desc = ObjectDescriptor::new();
    desc.id = id;
    desc.object_type = ObjectType::AuthenticationKey;
    desc.label = "Audit auth key".to_string();
    desc.domains = domains.clone();
    desc.capabilities = AUDIT_AUTHKEY_CAPABILITIES.to_vec();
    desc.delegated_capabilities = None;
    let auditkey = AuthenticationKey {
        descriptor: desc.clone(),
        auth_type: AuthenticationType::PasswordDerived,
        key: password.into_bytes(),
    };
    desc.id = import_authkey(session, &auditkey)?;
    Ok(desc)
}

pub fn setup_ksp(session: &Session,
                 current_authkey: &ObjectDescriptor,
                 rsa_decrypt: bool,
                 wrapkey_input: &KspWrapKeyInput,
                 appkey_input: &KspAuthKeyInput,
                 auditkey_input: Option<KspAuthKeyInput>
             ) -> Result<KspSetup, MgmError>{
    check_privileges(current_authkey)?;

    let (wrapkey_id, wrapkey_shares) = import_ksp_wrapkey(
        session,
        wrapkey_input.id,
        &wrapkey_input.domains,
        rsa_decrypt,
        wrapkey_input.shares,
        wrapkey_input.threshold,
    )?;

    let appkey_desc = import_app_authkey(
        session,
        appkey_input.id,
        &wrapkey_input.domains,
        rsa_decrypt,
        appkey_input.password.clone(),
    )?;

    let auditkey_desc = if let Some(auditkey_params) = auditkey_input {
        Some(import_audit_authkey(
            session,
            auditkey_params.id,
            &wrapkey_input.domains,
            auditkey_params.password.clone(),
        )?)
    } else {
        None
    };


    Ok(KspSetup {
        wrapkey_id: wrapkey_id,
        wrapkey: wrapkey_shares,
        appkey_desc: appkey_desc,
        auditkey_desc: auditkey_desc,
    })
}




fn get_capabilities(capabilities: &[ObjectCapability], expand: bool) -> Vec<ObjectCapability> {
    let mut caps = capabilities.to_vec();
    if expand {
        caps.extend_from_slice(&RSA_DECRYPT_CAPABILITIES);
    }
    caps
}