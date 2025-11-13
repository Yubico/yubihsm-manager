use std::fmt;
use std::fmt::Display;
use openssl::base64;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::common::get_authorized_commands;
use crate::backend::types::{CommandSpec, YhCommand};
use crate::backend::asym::AsymOps;
use crate::backend::common::{contains_all};
use crate::backend::object_ops::Importable;
use crate::backend::types::ImportObjectSpec;
use crate::backend::sym::SymOps;
use crate::backend::common::get_descriptors_from_handlers;
use crate::backend::object_ops::{Deletable, Generatable, Obtainable};
use crate::backend::types::{ObjectSpec};
use crate::error::MgmError;

pub struct WrapOps;

// 2 object ID bytes + 2 domains bytes + 8 capabilities bytes + 8 delegated capabilities = 20 bytes
const WRAP_SPLIT_PREFIX_LEN: usize = 20;

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

impl Obtainable for WrapOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut keys = session.list_objects_with_filter(
            0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
        keys.extend_from_slice(&session.list_objects_with_filter(
            0, ObjectType::PublicWrapKey, "", ObjectAlgorithm::ANY,
            &Vec::new())?);
        get_descriptors_from_handlers(session, keys.as_slice())
    }

    fn get_object_algorithms() -> Vec<MgmAlgorithm> {
        MgmAlgorithm::WRAP_KEY_ALGORITHMS.to_vec()
    }

    fn get_object_capabilities(_object_algorithm: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        unimplemented!()
    }
}

impl Deletable for WrapOps {
    fn delete(&self, session: &Session, object_id: u16, object_type: ObjectType) -> Result<(), MgmError> {
        session.delete_object(object_id, object_type)?;
        Ok(())
    }
}

impl Generatable for WrapOps {
    fn generate(&self, session: &Session, spec: &ObjectSpec) -> Result<u16, MgmError> {
        let id = session
            .generate_wrap_key(
                spec.id,
                &spec.label,
                &spec.domains,
                &spec.capabilities,
                spec.algorithm,
                &spec.delegated_capabilities)?;
        Ok(id)
    }
}

impl Importable for WrapOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        let id = match spec.object.object_type {
            ObjectType::WrapKey => session.import_wrap_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                spec.object.algorithm,
                &spec.object.delegated_capabilities,
                &spec.data[0])?,
            ObjectType::PublicWrapKey => session.import_public_wrap_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                spec.object.algorithm,
                &spec.object.delegated_capabilities,
                &spec.data[0])?,
            _ => {
                return Err(MgmError::InvalidInput(
                    "ImportObjectSpec has invalid object type for wrap key".to_string(),
                ));
            }
        };
        Ok(id)
    }
}

impl WrapOps {

    const WRAP_COMMANDS: [CommandSpec;12] = [
        CommandSpec {
            command: YhCommand::List,
            label: "List",
            description: "List all wrap keys stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        CommandSpec {
            command: YhCommand::GetKeyProperties,
            label: "Get Object Properties",
            description: "Get properties of a wrap key stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Generate,
            label: "Generate",
            description: "Generate a new wrap key inside the YubiHSM",
            required_capabilities: &[ObjectCapability::GenerateWrapKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Import,
            label: "Import",
            description: "Import a wrap key into the YubiHSM",
            required_capabilities: &[ObjectCapability::PutWrapKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Delete,
            label: "Delete",
            description: "Delete a wrap key from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteWrapKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::GetPublicKey,
            label: "Get Public Key",
            description: "Retrieve the public key portion of an RSA wrap key stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::ExportWrapped,
            label: "Export objects under wrap",
            description: "Writes files ending with .yhw to specified directory",
            required_capabilities: &[ObjectCapability::ExportWrapped],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::ImportWrapped,
            label: "Import wrapped object",
            description: "Reads one file ending with .yhw and imports the wrapped object",
            required_capabilities: &[ObjectCapability::ImportWrapped],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::BackupDevice,
            label: "Backup device",
            description: "Exports all exportable objects under wrap",
            required_capabilities: &[ObjectCapability::ExportWrapped],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::RestoreDevice,
            label: "Restore device",
            description: "Reads all files ending with .yhw in a specified directory and imports the wrapped objects",
            required_capabilities: &[ObjectCapability::ImportWrapped],
            require_all_capabilities: false,
        },
        CommandSpec::RETURN_COMMAND,
        CommandSpec::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<CommandSpec> {
        get_authorized_commands(authkey, &Self::WRAP_COMMANDS)
    }

    pub fn get_algorithm_from_keylen(keylen: usize) -> Result<ObjectAlgorithm, MgmError> {
        match keylen {
            16 => Ok(ObjectAlgorithm::Aes128CcmWrap),
            24 => Ok(ObjectAlgorithm::Aes192CcmWrap),
            32 => Ok(ObjectAlgorithm::Aes256CcmWrap),
            _ => Err(MgmError::Error(format!("Unsupported key length {}", keylen))),
        }
    }


    pub fn get_wrapkey_capabilities(key_type: WrapKeyType) -> Vec<ObjectCapability> {
        match key_type {
            WrapKeyType::Aes => AES_WRAP_KEY_CAPABILITIES.to_vec(),
            WrapKeyType::Rsa => RSA_WRAP_KEY_CAPABILITIES.to_vec(),
            WrapKeyType::RsaPublic => PUBLIC_WRAP_KEY_CAPABILITIES.to_vec(),
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
            Ok(get_descriptors_from_handlers(session, keys.as_slice())?)
        } else {
            let keys = session.list_objects_with_filter(
                0, ObjectType::WrapKey, "", ObjectAlgorithm::ANY, &Vec::new())?;
            let mut keys = get_descriptors_from_handlers(session, keys.as_slice())?;
            if key_type == WrapKeyType::Aes {
                keys.retain(|k| !AsymOps::is_rsa_key_algorithm(&k.algorithm));
            } else if key_type == WrapKeyType::Rsa {
                keys.retain(|k| AsymOps::is_rsa_key_algorithm(&k.algorithm));
            }
            Ok(keys)
        }
    }

    pub fn get_rsa_wrapkeys(session:&Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut keys = Self.get_all_objects(session)?;
        keys.retain(|k| AsymOps::is_rsa_key_algorithm(&k.algorithm));
        Ok(keys)
    }

    pub fn get_wrapping_keys(session:&Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if !authkey.capabilities.contains(&ObjectCapability::ExportWrapped) {
            return Ok(Vec::new());
        }
        let mut keys = Self::get_wrapkeys_by_type(session, WrapKeyType::Aes)?;
        keys.extend_from_slice(&Self::get_wrapkeys_by_type(session, WrapKeyType::RsaPublic)?);
        keys.retain(|k| k.capabilities.contains(&ObjectCapability::ExportWrapped));
        Ok(keys)
    }

    pub fn get_unwrapping_keys(session:&Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        if !authkey.capabilities.contains(&ObjectCapability::ImportWrapped) {
            return Ok(Vec::new());
        }
        let mut keys = Self::get_wrapkeys_by_type(session, WrapKeyType::Aes)?;
        keys.extend_from_slice(&Self::get_wrapkeys_by_type(session, WrapKeyType::Rsa)?);
        keys.retain(|k| k.capabilities.contains(&ObjectCapability::ImportWrapped));
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
        let mut objects = get_descriptors_from_handlers(session, objects.as_slice())?;
        objects.retain(|obj| contains_all(delegated, &obj.capabilities));
        if wrap_type == WrapType::Key {
            objects.retain(|obj| obj.object_type == ObjectType::AsymmetricKey || obj.object_type == ObjectType::SymmetricKey);
        }
        Ok(objects)
    }

    pub fn get_unwrapped_key_algorithms() -> Vec<MgmAlgorithm> {
        let mut algos = Vec::new();
        algos.extend_from_slice(AsymOps::get_object_algorithms().as_slice());
        algos.extend_from_slice(SymOps::get_object_algorithms().as_slice());
        algos
    }

    pub fn split_wrap_key(wrap_key:&ImportObjectSpec, threshold:u8, shares:u8) -> Result<WrapKeyShares, MgmError> {
        let mut split_key = WrapKeyShares {
            shares,
            threshold,
            shares_data: Vec::new(),
        };

        let mut data = Vec::<u8>::new();
        data.push(((wrap_key.object.id >> 8) & 0xff) as u8);
        data.push((wrap_key.object.id & 0xff) as u8);
        data.append(&mut ObjectDomain::bytes_from_slice(wrap_key.object.domains.as_slice()));
        data.append(&mut ObjectCapability::bytes_from_slice(wrap_key.object.capabilities.as_slice()));
        data.append(&mut ObjectCapability::bytes_from_slice(wrap_key.object.delegated_capabilities.as_slice()));
        data.extend_from_slice(wrap_key.data[0].as_slice());

        split_key.shares_data = rusty_secrets::generate_shares(threshold, shares, &data)?;

        Ok(split_key)
    }

    pub fn get_wrapkey_from_shares(shares:Vec<String>) -> Result<ImportObjectSpec, MgmError> {
        let data = rusty_secrets::recover_secret(shares)?;

        let key_len = data.len() - WRAP_SPLIT_PREFIX_LEN;

        if data.len() != WRAP_SPLIT_PREFIX_LEN + (key_len) {
            return Err(MgmError::Error(format!(
                "Wrong length for recovered secret: expected {}, found {}",
                WRAP_SPLIT_PREFIX_LEN + (key_len / 8),
                data.len()
            )));
        }

        let mut wrapkey_spec = ImportObjectSpec::empty();
        wrapkey_spec.object.object_type = ObjectType::WrapKey;
        wrapkey_spec.object.algorithm = WrapOps::get_algorithm_from_keylen(key_len)?;
        wrapkey_spec.object.id = ((u16::from(data[0])) << 8) | u16::from(data[1]);
        wrapkey_spec.object.domains = ObjectDomain::from_bytes(&data[2..4])?;
        wrapkey_spec.object.capabilities = ObjectCapability::from_bytes(&data[4..12])?;
        wrapkey_spec.object.delegated_capabilities = ObjectCapability::from_bytes(&data[12..20])?;

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
                    let mgf1_algo = AsymOps::get_mgf1_algorithm(&oaep_algo)?;

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

    pub fn import_wrapped(session: &Session, wrap_op_spec: &WrapOpSpec, wrapped: String, new_key_spec: Option<ObjectSpec>) -> Result<ObjectHandle, MgmError> {
        let data = base64::decode_block(&wrapped)?;

        let handle = match wrap_op_spec.wrapkey_type {
            WrapKeyType::Aes => session.import_wrapped(wrap_op_spec.wrapkey_id, &data)?,
            WrapKeyType::Rsa => {
                let oaep_algo = match wrap_op_spec.oaep_algorithm {
                    Some(algo) => algo,
                    None => ObjectAlgorithm::RsaOaepSha256,
                };
                let oaep_label = Self::get_oaep_label(&oaep_algo)?;
                let mgf1_algo = AsymOps::get_mgf1_algorithm(&oaep_algo)?;
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
        let oaep_label:&[u8;64] = &[0;64];
        AsymOps::get_hashed_bytes(algorithm, oaep_label)
    }
}