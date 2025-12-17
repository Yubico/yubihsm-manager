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
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::traits::operation_traits::YubihsmOperations;
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::types::{MgmCommand, MgmCommandType, NewObjectSpec};
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::common::{contains_all, get_object_descriptors};
use crate::hsm_operations::sym::SymmetricOperations;


// 2 object ID bytes + 2 domains bytes + 8 capabilities bytes + 8 delegated capabilities = 20 bytes
static WRAP_SPLIT_PREFIX_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WrapKeyType {
    #[default]
    Aes,
    Rsa,
    RsaPublic,
}

pub struct WrapKeyShares {
    pub shares: u8,
    pub threshold: u8,
    pub shares_data: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WrapType {
    #[default]
    Object,
    Key,
}

impl Display for WrapType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WrapType::Object => write!(f, "YubiHSM2 Object"),
            WrapType::Key => write!(f, "Key data only"),
        }
    }
}

pub struct WrapOpSpec {
    pub wrapkey_id: u16,
    pub wrapkey_type: WrapKeyType,
    pub wrap_type: WrapType,
    pub include_ed_seed: bool,
    pub aes_algorithm: Option<ObjectAlgorithm>,
    pub oaep_algorithm: Option<ObjectAlgorithm>,
    pub mgf1_algorithm: Option<ObjectAlgorithm>,
}

pub struct WrappedData {
    pub object_id: u16,
    pub object_type: ObjectType,
    pub wrapkey_id: u16,
    pub wrapped_data: Vec<u8>,
    pub error: Option<MgmError>,
}

const AES_WRAP_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::ExportWrapped,
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportableUnderWrap,
];

const RSA_WRAP_KEY_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::ImportWrapped,
    ObjectCapability::ExportableUnderWrap,
];

const PUBLIC_WRAP_KEY_CAPABILITIES: [ObjectCapability; 2] = [
    ObjectCapability::ExportWrapped,
    ObjectCapability::ExportableUnderWrap,
];

pub struct WrapOperations;

impl YubihsmOperations for WrapOperations {
    fn get_commands(&self) -> Vec<MgmCommand> {
        [
            MgmCommand {
                command: MgmCommandType::List,
                label: "List",
                description: "List all wrap keys stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false
            },
            MgmCommand {
                command: MgmCommandType::GetKeyProperties,
                label: "Get Object Properties",
                description: "Get properties of a wrap key stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Generate,
                label: "Generate",
                description: "Generate a new wrap key inside the YubiHSM",
                required_capabilities: &[ObjectCapability::GenerateWrapKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Import,
                label: "Import",
                description: "Import a wrap key into the YubiHSM",
                required_capabilities: &[ObjectCapability::PutWrapKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Delete,
                label: "Delete",
                description: "Delete a wrap key from the YubiHSM",
                required_capabilities: &[ObjectCapability::DeleteWrapKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::GetPublicKey,
                label: "Get Public Key",
                description: "Retrieve the public key portion of an RSA wrap key stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::ExportWrapped,
                label: "Export objects under wrap",
                description: "Writes files ending with .yhw to specified directory",
                required_capabilities: &[ObjectCapability::ExportWrapped],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::ImportWrapped,
                label: "Import wrapped object",
                description: "Get pseudo random bytes generated by the YubiHSM",
                required_capabilities: &[ObjectCapability::GetPseudoRandom],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::GetRandom,
                label: "Generate pseudo random number",
                description: "Exports all exportable objects under wrap",
                required_capabilities: &[ObjectCapability::ExportWrapped],
                require_all_capabilities: false,
            },
            MgmCommand::EXIT_COMMAND,
        ].to_vec()
    }

    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut keys = session.list_objects_with_filter(
            0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
        keys.extend_from_slice(&session.list_objects_with_filter(
            0, ObjectType::PublicWrapKey, "", ObjectAlgorithm::ANY,
            &Vec::new())?);
        get_object_descriptors(session, &keys)
    }

    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm> {
        MgmAlgorithm::WRAP_KEY_ALGORITHMS.to_vec()
    }

    fn get_object_capabilities(
        &self,
        object_type: Option<ObjectType>,
        object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {

        if object_type.is_none() || object_algorithm.is_none() {
            return Err(MgmError::InvalidInput(
                "Missing object type and/or object algorithm".to_string(),
            ));
        }

        let key_type = Self::get_wrapkey_type(
            object_type.unwrap(),
            object_algorithm.unwrap(),
        )?;

        match key_type {
            WrapKeyType::Aes => Ok(AES_WRAP_KEY_CAPABILITIES.to_vec()),
            WrapKeyType::Rsa => Ok(RSA_WRAP_KEY_CAPABILITIES.to_vec()),
            WrapKeyType::RsaPublic => Ok(PUBLIC_WRAP_KEY_CAPABILITIES.to_vec()),
        }
    }

    fn generate(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        let id = session
            .generate_wrap_key(
                spec.id,
                &spec.label,
                &spec.domains,
                &spec.capabilities,
                spec.algorithm,
                &spec.delegated_capabilities)?;
        Ok(id)    }

    fn import(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        let id = match spec.object_type {
            ObjectType::WrapKey => session.import_wrap_key(
                spec.id,
                &spec.label,
                &spec.domains,
                &spec.capabilities,
                spec.algorithm,
                &spec.delegated_capabilities,
                &spec.data[0])?,
            ObjectType::PublicWrapKey => session.import_public_wrap_key(
                spec.id,
                &spec.label,
                &spec.domains,
                &spec.capabilities,
                spec.algorithm,
                &spec.delegated_capabilities,
                &spec.data[0])?,
            _ => {
                return Err(MgmError::InvalidInput(
                    "ImportObjectSpec has invalid object type for wrap key".to_string(),
                ));
            }
        };
        Ok(id)    }
}

impl WrapOperations {

    pub fn get_algorithm_from_keylen(keylen: usize) -> Result<ObjectAlgorithm, MgmError> {
        match keylen {
            16 => Ok(ObjectAlgorithm::Aes128CcmWrap),
            24 => Ok(ObjectAlgorithm::Aes192CcmWrap),
            32 => Ok(ObjectAlgorithm::Aes256CcmWrap),
            256 => Ok(ObjectAlgorithm::Rsa2048),
            384 => Ok(ObjectAlgorithm::Rsa3072),
            512 => Ok(ObjectAlgorithm::Rsa4096),
            _ => Err(MgmError::Error(format!("Unsupported key length {}", keylen))),
        }
    }

    pub fn get_wrapkey_type(object_type: ObjectType, algorithm: ObjectAlgorithm) -> Result<WrapKeyType, MgmError> {
        match object_type {
            ObjectType::PublicWrapKey => Ok(WrapKeyType::RsaPublic),
            ObjectType::WrapKey => match algorithm {
                ObjectAlgorithm::Aes128CcmWrap |
                ObjectAlgorithm::Aes192CcmWrap |
                ObjectAlgorithm::Aes256CcmWrap => Ok(WrapKeyType::Aes),
                ObjectAlgorithm::Rsa2048 |
                ObjectAlgorithm::Rsa3072 |
                ObjectAlgorithm::Rsa4096 => Ok(WrapKeyType::Rsa),
                _ => {
                    Err(MgmError::InvalidInput(
                        "Unsupported algorithm for wrap key".to_string(),
                    ))
                }
            },
            _ => Err(MgmError::InvalidInput(
                "Unsupported object type for wrap key".to_string(),
            )),
        }
    }

    fn get_wrapkeys_by_type(session:&Session, key_type:WrapKeyType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if key_type == WrapKeyType::RsaPublic {
            let keys = session.list_objects_with_filter(
                0, ObjectType::PublicWrapKey, "", ObjectAlgorithm::ANY,
                &Vec::new())?;
            Ok(get_object_descriptors(session, keys.as_slice())?)
        } else {
            let keys = session.list_objects_with_filter(
                0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
            let mut keys = get_object_descriptors(session, keys.as_slice())?;
            if key_type == WrapKeyType::Aes {
                keys.retain(|k| !AsymmetricOperations::is_rsa_key_algorithm(&k.algorithm));
            } else if key_type == WrapKeyType::Rsa {
                keys.retain(|k| AsymmetricOperations::is_rsa_key_algorithm(&k.algorithm));
            }
            Ok(keys)
        }
    }

    pub fn get_rsa_wrapkeys(session:&Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut keys = Self.get_all_objects(session)?;
        keys.retain(|k| AsymmetricOperations::is_rsa_key_algorithm(&k.algorithm));
        Ok(keys)
    }

    pub fn get_wrapping_keys(session:&Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if !authkey.capabilities.contains(&ObjectCapability::ExportWrapped) {
            return Ok(Vec::new());
        }
        let mut keys = Self::get_wrapkeys_by_type(session, WrapKeyType::Aes)?;
        keys.extend_from_slice(&Self::get_wrapkeys_by_type(session, WrapKeyType::RsaPublic)?);
        keys.retain(|k| k.capabilities.contains(&ObjectCapability::ExportWrapped));
        if keys.is_empty() {
            return Err(MgmError::Error(
                format!("No wrap keys with {:?} capability were found", ObjectCapability::ExportWrapped)));
        }
        Ok(keys)
    }

    pub fn get_unwrapping_keys(session:&Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if !authkey.capabilities.contains(&ObjectCapability::ImportWrapped) {
            return Ok(Vec::new());
        }
        let mut keys = Self::get_wrapkeys_by_type(session, WrapKeyType::Aes)?;
        keys.extend_from_slice(&Self::get_wrapkeys_by_type(session, WrapKeyType::Rsa)?);
        keys.retain(|k| k.capabilities.contains(&ObjectCapability::ImportWrapped));
        if keys.is_empty() {
            return Err(MgmError::Error(
                format!("No wrap keys with {:?} capability were found", ObjectCapability::ImportWrapped)));
        }
        Ok(keys)
    }

    pub fn get_exportable_objects(session: &Session, wrap_key: &ObjectDescriptor, wrap_type: WrapType) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if wrap_key.delegated_capabilities.is_none() {
            return Ok(Vec::new());
        }
        let delegated = wrap_key.delegated_capabilities.as_ref().unwrap();

        let objects = session.list_objects_with_filter(
            0,
            ObjectType::Any,
            "",
            ObjectAlgorithm::ANY,
            &[ObjectCapability::ExportableUnderWrap])?;
        let mut objects = get_object_descriptors(session, objects.as_slice())?;
        objects.retain(|obj| contains_all(delegated, &obj.capabilities));
        if wrap_type == WrapType::Key {
            objects.retain(|obj| obj.object_type == ObjectType::AsymmetricKey || obj.object_type == ObjectType::SymmetricKey);
        }
        Ok(objects)
    }

    pub fn get_unwrapped_key_algorithms() -> Vec<MgmAlgorithm> {
        let mut algos = Vec::new();
        algos.extend_from_slice(AsymmetricOperations.get_generation_algorithms().as_slice());
        algos.extend_from_slice(SymmetricOperations.get_generation_algorithms().as_slice());
        algos
    }

    pub fn split_wrap_key(wrap_key:&NewObjectSpec, threshold:u8, shares:u8) -> Result<WrapKeyShares, MgmError> {
        let mut split_key = WrapKeyShares {
            shares,
            threshold,
            shares_data: Vec::new(),
        };

        let mut data = Vec::<u8>::new();
        data.push(((wrap_key.id >> 8) & 0xff) as u8);
        data.push((wrap_key.id & 0xff) as u8);
        data.append(&mut ObjectDomain::bytes_from_slice(wrap_key.domains.as_slice()));
        data.append(&mut ObjectCapability::bytes_from_slice(wrap_key.capabilities.as_slice()));
        data.append(&mut ObjectCapability::bytes_from_slice(wrap_key.delegated_capabilities.as_slice()));
        data.extend_from_slice(wrap_key.data[0].as_slice());

        split_key.shares_data = rusty_secrets::generate_shares(threshold, shares, &data)?;

        Ok(split_key)
    }

    pub fn get_wrapkey_from_shares(shares:Vec<String>) -> Result<NewObjectSpec, MgmError> {
        let data = rusty_secrets::recover_secret(shares)?;

        let key_len = data.len() - WRAP_SPLIT_PREFIX_LEN;

        if data.len() != WRAP_SPLIT_PREFIX_LEN + (key_len) {
            return Err(MgmError::Error(format!(
                "Wrong length for recovered secret: expected {}, found {}",
                WRAP_SPLIT_PREFIX_LEN + (key_len / 8),
                data.len()
            )));
        }

        let mut wrapkey_spec = NewObjectSpec::empty();
        wrapkey_spec.object_type = ObjectType::WrapKey;
        wrapkey_spec.algorithm = WrapOperations::get_algorithm_from_keylen(key_len)?;
        wrapkey_spec.id = ((u16::from(data[0])) << 8) | u16::from(data[1]);
        wrapkey_spec.domains = ObjectDomain::from_bytes(&data[2..4])?;
        wrapkey_spec.capabilities = ObjectCapability::from_bytes(&data[4..12])?;
        wrapkey_spec.delegated_capabilities = ObjectCapability::from_bytes(&data[12..20])?;

        wrapkey_spec.data.push(data[20..].to_vec());

        Ok(wrapkey_spec)
    }

    pub fn export_wrapped(session: &Session, wrap_op_spec: &WrapOpSpec, export_objects: &Vec<ObjectDescriptor>) -> Result<Vec<WrappedData>, MgmError> {
        let mut wrapped = Vec::new();
        for object in export_objects {
            let mut w = WrappedData {
                object_id: object.id,
                object_type: object.object_type,
                wrapkey_id: wrap_op_spec.wrapkey_id,
                wrapped_data: Vec::new(),
                error: None,
            };

            let res = match wrap_op_spec.wrapkey_type {
                WrapKeyType::Aes => {
                    let format: u8 = if wrap_op_spec.include_ed_seed { 1 } else { 0 };
                    session.export_wrapped_ex(wrap_op_spec.wrapkey_id, object.object_type, object.id, format)
                },
                WrapKeyType::RsaPublic => {
                    let aes_algo = match wrap_op_spec.aes_algorithm {
                        Some(algo) => algo,
                        None => ObjectAlgorithm::Aes256,
                    };

                    let oaep_algo = match wrap_op_spec.oaep_algorithm {
                        Some(algo) => algo,
                        None => ObjectAlgorithm::RsaOaepSha256,
                    };

                    let oaep_label = Self::get_oaep_label(&oaep_algo)?;
                    let mgf1_algo = match wrap_op_spec.mgf1_algorithm {
                        Some(algo) => algo,
                        None => ObjectAlgorithm::Mgf1Sha256,
                    };

                    match wrap_op_spec.wrap_type {
                        WrapType::Object => session.export_rsa_wrapped_object(
                            wrap_op_spec.wrapkey_id,
                            object.object_type,
                            object.id,
                            aes_algo,
                            oaep_algo,
                            mgf1_algo,
                            &oaep_label,
                        ),
                        WrapType::Key => session.export_rsa_wrapped_key(
                            wrap_op_spec.wrapkey_id,
                            object.object_type,
                            object.id,
                            aes_algo,
                            oaep_algo,
                            mgf1_algo,
                            &oaep_label,
                        ),
                    }
                },
                WrapKeyType::Rsa => {
                    return Err(MgmError::InvalidInput("Private RSA key cannot be used for wrapping".to_string()))
                }
            };

            match res {
                Ok(bytes) => w.wrapped_data = bytes,
                Err(err) => w.error = Some(MgmError::LibYubiHsm(err))
            }
            wrapped.push(w);
        }
        Ok(wrapped)
    }

    pub fn import_wrapped(session: &Session, wrap_op_spec: &WrapOpSpec, wrapped: &[u8], new_key_spec: Option<NewObjectSpec>) -> Result<ObjectHandle, MgmError> {
        let data = wrapped.to_vec();

        let handle = match wrap_op_spec.wrapkey_type {
            WrapKeyType::Aes => session.import_wrapped(wrap_op_spec.wrapkey_id, &data)?,
            WrapKeyType::Rsa => {
                let oaep_algo = match wrap_op_spec.oaep_algorithm {
                    Some(algo) => algo,
                    None => ObjectAlgorithm::RsaOaepSha256,
                };
                let oaep_label = Self::get_oaep_label(&oaep_algo)?;
                let mgf1_algo = match wrap_op_spec.mgf1_algorithm {
                    Some(algo) => algo,
                    None => ObjectAlgorithm::Mgf1Sha256,
                };
                match wrap_op_spec.wrap_type {
                    WrapType::Object => session.import_rsa_wrapped_object(
                        wrap_op_spec.wrapkey_id,
                        oaep_algo,
                        mgf1_algo,
                        &oaep_label,
                        &data,
                    )?,
                    WrapType::Key => {
                        if new_key_spec.is_none() {
                            return Err(MgmError::InvalidInput("Object parameters for the imported wrapped key is missing".to_string()));
                        }
                        let key_spec = new_key_spec.unwrap();
                        session.import_rsa_wrapped_key(
                            wrap_op_spec.wrapkey_id,
                            key_spec.object_type,
                            key_spec.id,
                            key_spec.algorithm,
                            &key_spec.label,
                            &key_spec.domains,
                            &key_spec.capabilities,
                            oaep_algo,
                            mgf1_algo,
                            &oaep_label,
                            &data,
                        )?
                    }
                }
            }
            WrapKeyType::RsaPublic => {
                return Err(MgmError::InvalidInput("Public RSA key cannot be used for unwrapped".to_string()))
            }
        };

        Ok(handle)
    }

    fn get_oaep_label(algorithm: &ObjectAlgorithm) -> Result<Vec<u8>, MgmError> {
        let oaep_label: &[u8] = &[];
        AsymmetricOperations::get_hashed_bytes(algorithm, oaep_label)
    }
}