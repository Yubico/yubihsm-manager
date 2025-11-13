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

use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::string::ToString;
use pem::Pem;
use openssl::pkey;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};
use yubihsmrs::Session;
use crate::backend::algorithms::MgmAlgorithm;
use crate::backend::error::MgmError;
use crate::backend::common::{get_authorized_commands, get_op_keys};
use crate::backend::object_ops::Importable;
use crate::backend::types::{ImportObjectSpec};
use crate::backend::object_ops::{Deletable, Generatable};
use crate::backend::types::{CommandSpec, ObjectSpec, YhCommand};
use crate::backend::common::get_descriptors_from_handlers;
use crate::backend::object_ops::Obtainable;

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AsymmetricType {
    #[default]
    Key,
    X509Certificate,
}

impl Display for AsymmetricType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsymmetricType::Key => write!(f, "Private keys"),
            AsymmetricType::X509Certificate => write!(f, "X509Certificates"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AttestationType {
    #[default]
    DeviceSigned,
    SelfSigned,
    AsymSigned,
}

impl Display for AttestationType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttestationType::DeviceSigned => write!(f, "Signed by device attestation key"),
            AttestationType::SelfSigned => write!(f, "Self signed"),
            AttestationType::AsymSigned => write!(f, "Signed by another asymmetric key"),
        }
    }
}

pub struct AsymOps;

impl Obtainable for AsymOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        Self::get_asymmetric_objects(session, &[AsymmetricType::Key, AsymmetricType::X509Certificate])
    }

    fn get_object_algorithms() -> Vec<MgmAlgorithm> {
        let mut algos = MgmAlgorithm::RSA_KEY_ALGORITHMS.to_vec();
        algos.extend(MgmAlgorithm::EC_KEY_ALGORITHMS.to_vec());
        algos.extend(MgmAlgorithm::ED_KEY_ALGORITHMS.to_vec());
        algos
    }

    fn get_object_capabilities(object_algorithm: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        if Self::is_rsa_key_algorithm(object_algorithm) {
            Self::RSA_KEY_CAPABILITIES.to_vec()
        } else if Self::is_ec_key_algorithm(object_algorithm) {
            Self::EC_KEY_CAPABILITIES.to_vec()
        } else if *object_algorithm == ObjectAlgorithm::Ed25519 {
            Self::ED_KEY_CAPABILITIES.to_vec()
        } else if *object_algorithm == ObjectAlgorithm::OpaqueX509Certificate {
            Self::OPAQUE_CAPABILITIES.to_vec()
        } else {
            Vec::new()
        }
    }
}

// impl Describable for AsymOps {
//     fn get_properties(&self, session: &Session, id: u16, object_type: ObjectType) -> Result<ObjectDescriptor, MgmError> {
//         Ok(session.get_object_info(id, object_type)?)
//     }
// }


impl Deletable for AsymOps {
    fn delete(&self, session: &Session, object_id: u16, object_type: ObjectType) -> Result<(), MgmError> {
        Ok(session.delete_object(object_id, object_type)?)
    }
}

impl Generatable for AsymOps {
    fn generate(&self, session: &Session, spec: &ObjectSpec) -> Result<u16, MgmError> {
        let key = session
            .generate_asymmetric_key_with_keyid(
                spec.id, &spec.label, &spec.capabilities, &spec.domains, spec.algorithm)?;
        Ok(key.get_key_id())
    }
}

impl Importable for AsymOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        let key_data = &spec.data[0];
        let id =
        if Self::is_rsa_key_algorithm(&spec.object.algorithm) {
            session.import_rsa_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                spec.object.algorithm,
                &key_data[0..key_data.len() / 2],
                &key_data[key_data.len() / 2..])?
        } else if Self::is_ec_key_algorithm(&spec.object.algorithm) {
            session.import_ec_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                spec.object.algorithm,
                key_data)?
        } else if spec.object.algorithm == ObjectAlgorithm::Ed25519 {
            session.import_ed_key(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                key_data)?
        } else if spec.object.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
            session.import_cert(
                spec.object.id,
                &spec.object.label,
                &spec.object.domains,
                &spec.object.capabilities,
                key_data)?
        } else {
            return Err(MgmError::InvalidInput(
                format!("Unsupported asymmetric key algorithm {:?}", spec.object.algorithm)));
        };
        Ok(id)
    }
}




//----------------------------------------------------------
//       Main symmetric functions requiring a session
//----------------------------------------------------------

impl AsymOps {

    const RSA_KEY_CAPABILITIES: [ObjectCapability; 6] = [
        ObjectCapability::SignPkcs,
        ObjectCapability::SignPss,
        ObjectCapability::DecryptPkcs,
        ObjectCapability::DecryptOaep,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::SignAttestationCertificate];

    const EC_KEY_CAPABILITIES: [ObjectCapability; 4] = [
        ObjectCapability::SignEcdsa,
        ObjectCapability::DeriveEcdh,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::SignAttestationCertificate];

    const ED_KEY_CAPABILITIES: [ObjectCapability; 3] = [
        ObjectCapability::SignEddsa,
        ObjectCapability::ExportableUnderWrap,
        ObjectCapability::SignAttestationCertificate];

    const OPAQUE_CAPABILITIES: [ObjectCapability; 1] = [
        ObjectCapability::ExportableUnderWrap];

    const ASYM_COMMANDS: [CommandSpec;13] = [
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
            required_capabilities: &[ObjectCapability::GenerateAsymmetricKey],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Import,
            label: "Import",
            description: "Import an asymmetric key or X509 certificate into the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Delete,
            label: "Delete",
            description: "Delete an asymmetric key or X509 certificate from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteAsymmetricKey,
            ObjectCapability::DeleteOpaque],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::GetPublicKey,
            label: "Get Public Key",
            description: "Retrieve the public key portion of an asymmetric key stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::GetCertificate,
            label: "Get X509 Certificate",
            description: "Retrieve an X509 certificate stored in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Sign,
            label: "Sign",
            description: "Sign data using an asymmetric private key stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::SignEcdsa,
            ObjectCapability::SignEddsa],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::Decrypt,
            label: "Decrypt",
            description: "Decrypt data using an asymmetric private key stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::DecryptPkcs,
            ObjectCapability::DecryptOaep],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::DeriveEcdh,
            label: "Derive ECDH",
            description: "Derive an ECDH shared secret using an EC private key stored in the YubiHSM",
            required_capabilities: &[ObjectCapability::DeriveEcdh],
            require_all_capabilities: false,
        },
        CommandSpec {
            command: YhCommand::SignAttestationCert,
            label: "Sign Attestation Certificate",
            description: "Generate and sign an attestation certificate for a key generated on the YubiHSM",
            required_capabilities: &[ObjectCapability::SignAttestationCertificate],
            require_all_capabilities: false,
        },
        CommandSpec::RETURN_COMMAND,
        CommandSpec::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<CommandSpec> {
        get_authorized_commands(authkey, &Self::ASYM_COMMANDS)
    }

    pub fn get_asymmetric_objects(session: &Session, types: &[AsymmetricType]) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut objects = Vec::new();
        if types.contains(&AsymmetricType::Key) {
            objects.extend(session.list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?);
        }
        if types.contains(&AsymmetricType::X509Certificate) {
            objects.extend(session.list_objects_with_filter(0, ObjectType::Opaque, "", ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
        }
        let mut objects = get_descriptors_from_handlers(session, &objects)?;
        objects.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(objects)
    }

    pub fn get_signing_keys(session: &Session, authkey: &ObjectDescriptor) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let caps = [
            ObjectCapability::SignPkcs,
            ObjectCapability::SignPss,
            ObjectCapability::SignEcdsa,
            ObjectCapability::SignEddsa
        ];
        let mut keys =
            get_op_keys(session, authkey, &caps, ObjectType::AsymmetricKey, None)?;

        keys.retain(|k| {
            (Self::is_rsa_key_algorithm(&k.algorithm) && (k.capabilities.contains(&ObjectCapability::SignPkcs) || k.capabilities.contains(&ObjectCapability::SignPss))) ||
            (Self::is_ec_key_algorithm(&k.algorithm) && k.capabilities.contains(&ObjectCapability::SignEcdsa)) ||
            (k.algorithm == ObjectAlgorithm::Ed25519 && k.capabilities.contains(&ObjectCapability::SignEddsa))
        });
        Ok(keys)
    }

    pub fn get_decryption_keys(session: &Session, authkey: &ObjectDescriptor)  -> Result<Vec<ObjectDescriptor>, MgmError> {
        let caps = [
            ObjectCapability::DecryptPkcs,
            ObjectCapability::DecryptOaep,
        ];
        get_op_keys(session, authkey, &caps, ObjectType::AsymmetricKey, Some(&MgmAlgorithm::extract_algorithms(&MgmAlgorithm::RSA_KEY_ALGORITHMS)))
    }

    pub fn get_derivation_keys(session: &Session, authkey: &ObjectDescriptor)  -> Result<Vec<ObjectDescriptor>, MgmError> {
        get_op_keys(session, authkey, &[ObjectCapability::DeriveEcdh], ObjectType::AsymmetricKey, Some(&MgmAlgorithm::extract_algorithms(&MgmAlgorithm::EC_KEY_ALGORITHMS)))
    }

    pub fn get_signing_algorithms(authkey: &ObjectDescriptor, signkey: &ObjectDescriptor) -> Vec<MgmAlgorithm> {
        let mut algos = Vec::new();
        if Self::is_rsa_key_algorithm(&signkey.algorithm) {
            if signkey.capabilities.contains(&ObjectCapability::SignPkcs) &&
                authkey.capabilities.contains(&ObjectCapability::SignPkcs) {
                algos.extend_from_slice(&MgmAlgorithm::RSA_PKCS_ALGORITHMS);
            }
            if signkey.capabilities.contains(&ObjectCapability::SignPss) &&
                authkey.capabilities.contains(&ObjectCapability::SignPss) {
                algos.extend_from_slice(&MgmAlgorithm::RSA_PSS_ALGORITHMS);
            }
        } else if Self::is_ec_key_algorithm(&signkey.algorithm) &&
            signkey.capabilities.contains(&ObjectCapability::SignEcdsa) &&
                authkey.capabilities.contains(&ObjectCapability::SignEcdsa) {
            algos.extend_from_slice(&MgmAlgorithm::ECDSA_ALGORITHMS);
        } else if signkey.algorithm == ObjectAlgorithm::Ed25519 &&
            signkey.capabilities.contains(&ObjectCapability::SignEddsa) &&
                authkey.capabilities.contains(&ObjectCapability::SignEddsa) {
                algos.extend_from_slice(&MgmAlgorithm::EDDSA_ALGORITHMS);
        }
        algos
    }

    pub fn get_decryption_algorithms(authkey: &ObjectDescriptor, deckey: &ObjectDescriptor) -> Vec<MgmAlgorithm> {
        let mut algos = Vec::new();
        if Self::is_rsa_key_algorithm(&deckey.algorithm) {
            if deckey.capabilities.contains(&ObjectCapability::DecryptPkcs) && authkey.capabilities.contains(&ObjectCapability::DecryptPkcs) {
                algos.push(MgmAlgorithm::RsaPkcs1Decrypt);
            }
            if deckey.capabilities.contains(&ObjectCapability::DecryptOaep) && authkey.capabilities.contains(&ObjectCapability::DecryptOaep) {
                algos.extend_from_slice(&MgmAlgorithm::RSA_OAEP_ALGORITHMS);
            }
        }
        algos
    }

    pub fn get_pubkey_pem(session: &Session, object_id: u16, object_typ: ObjectType) -> Result<Pem, MgmError> {
        let (pubkey, algo) = session.get_pubkey(object_id, object_typ)?;
        let pem_bytes: Vec<u8> = if Self::is_rsa_key_algorithm(&algo) {
            let e = BigNum::from_slice(&[0x01, 0x00, 0x01])?;
            let n = BigNum::from_slice(pubkey.as_slice())?;
            let rsa_pubkey = openssl::rsa::Rsa::from_public_components(n, e)?;
            rsa_pubkey.public_key_to_pem()?
        } else if Self::is_ec_key_algorithm(&algo) {
            let nid = match algo {
                ObjectAlgorithm::EcP256 => Nid::X9_62_PRIME256V1,
                ObjectAlgorithm::EcK256 => Nid::SECP256K1,
                ObjectAlgorithm::EcP384 => Nid::SECP384R1,
                ObjectAlgorithm::EcP521 => Nid::SECP521R1,
                ObjectAlgorithm::EcP224 => Nid::SECP224R1,
                ObjectAlgorithm::EcBp256 => Nid::BRAINPOOL_P256R1,
                ObjectAlgorithm::EcBp384 => Nid::BRAINPOOL_P384R1,
                ObjectAlgorithm::EcBp512 => Nid::BRAINPOOL_P512R1,
                _ => unreachable!()
            };
            let ec_group = EcGroup::from_curve_name(nid)?;
            let mut ctx = BigNumContext::new()?;

            let mut ec_pubkey_bytes: Vec<u8> = Vec::new();
            ec_pubkey_bytes.push(0x04);
            ec_pubkey_bytes.extend(pubkey);
            let ec_point = EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx)?;
            let ec_pubkey = EcKey::from_public_key(&ec_group, &ec_point)?;
            ec_pubkey.public_key_to_pem()?
        } else if algo == ObjectAlgorithm::Ed25519 {
            let ed_pubkey = PKey::public_key_from_raw_bytes(pubkey.as_slice(), pkey::Id::ED25519)?;
            ed_pubkey.public_key_to_pem()?
        } else {
            return Err(MgmError::InvalidInput(
                format!("Unknown or unsupported asymmetric key algorithm {:?}", algo)));
        };
        let pem = Pem::try_from(pem_bytes.as_slice())?;
        Ok(pem)
    }

    pub fn get_certificate(session: &Session, key_id: u16) -> Result<Pem, MgmError> {
        let data = session.get_opaque(key_id)?;
        let cert: Vec<u8> = match openssl::x509::X509::from_der(data.as_slice()) {
            Ok(cert) => cert.to_pem()?,
            Err(_) => return Err(MgmError::InvalidInput(format!("Opaque object 0x{:04x} is not an X509Certificate", key_id)))
        };
        Ok(Pem::try_from(cert.as_slice())?)
    }

    pub fn sign(session: &Session, sign_key_id: u16, sign_algorithm: &ObjectAlgorithm, data: &[u8]) -> Result<Vec<u8>, MgmError> {
        let sig = match sign_algorithm {
            ObjectAlgorithm::RsaPkcs1Sha1 | ObjectAlgorithm::RsaPkcs1Sha256 | ObjectAlgorithm::RsaPkcs1Sha384 | ObjectAlgorithm::RsaPkcs1Sha512 => {
                let hashed_bytes = Self::get_hashed_bytes(sign_algorithm, data)?;
                session.sign_pkcs1v1_5(sign_key_id, true, hashed_bytes.as_slice())?
            },
            ObjectAlgorithm::RsaPssSha1 | ObjectAlgorithm::RsaPssSha256 | ObjectAlgorithm::RsaPssSha384 | ObjectAlgorithm::RsaPssSha512 => {
                let hashed_bytes = Self::get_hashed_bytes(sign_algorithm, data)?;
                let mgf1_algo = Self::get_mgf1_algorithm(sign_algorithm)?;
                session.sign_pss(sign_key_id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?
            },
            ObjectAlgorithm::EcdsaSha1 | ObjectAlgorithm::EcdsaSha256 | ObjectAlgorithm::EcdsaSha384 | ObjectAlgorithm::EcdsaSha512 => {
                let hashed_bytes = Self::get_hashed_bytes(sign_algorithm, data)?;
                session.sign_ecdsa(sign_key_id, hashed_bytes.as_slice())?
            },
            ObjectAlgorithm::Ed25519 => {
                session.sign_eddsa(sign_key_id, data)?
            },
            _ => {
                return Err(MgmError::Error("Unsupported signing algorithm".to_string()))
            }
        };
        Ok(sig)
    }

    pub fn decrypt(session: &Session, decryption_key_id: u16, decryption_algorithm: &ObjectAlgorithm, ciphertext: &[u8]) -> Result<Vec<u8>, MgmError> {
        let data = if decryption_algorithm == &ObjectAlgorithm::RsaPkcs1Decrypt {
            session.decrypt_pkcs1v1_5(decryption_key_id, ciphertext)?
        } else if Self::is_oaep_algorithm(decryption_algorithm) {
            let oaep_label: &[u8; 64] = &[0; 64];
            let oaep_label = Self::get_hashed_bytes(decryption_algorithm, oaep_label)?;
            let mgf1_algo = Self::get_mgf1_algorithm(decryption_algorithm)?;
            session.decrypt_oaep(decryption_key_id, ciphertext, &oaep_label, mgf1_algo)?
        } else {
            return Err(MgmError::InvalidInput("Selected decryption algorithm is not supported".to_string()))
        };
        Ok(data)
    }

    pub fn derive_ecdh(session: &Session, hsm_key: &ObjectDescriptor, peer_pubkey: Pem) -> Result<Vec<u8>, MgmError> {
        let (peer_type, peer_algo, peer_key) = Self::parse_asym_pem(peer_pubkey)?;

        if peer_type != ObjectType::PublicKey || !Self::is_ec_key_algorithm(&peer_algo) {
            return Err(MgmError::InvalidInput("Peer public key is not an EC public key".to_string()))
        }

        if peer_algo != hsm_key.algorithm {
            return Err(MgmError::InvalidInput("Peer public key algorithm does not match HSM key algorithm".to_string()))
        }

        Ok(session.derive_ecdh(hsm_key.id, peer_key.as_slice())?)
    }

    pub fn get_attestation_cert(
        session: &Session,
        attested_key: u16,
        attesting_key: u16,
        template_cert: Option<Pem>) -> Result<Pem, MgmError> {
        let cert_bytes = if attesting_key == 0 {
            session.sign_attestation_certificate(attested_key, 0)?
        } else {
            let imported_template = Self::import_attestation_template(session, attesting_key, attested_key, template_cert)?;
            let cert = session.sign_attestation_certificate(attested_key, attesting_key)?;
            if imported_template {
                session.delete_object(attesting_key, ObjectType::Opaque)?;
            }
            cert
        };


        let cert: Vec<u8> = openssl::x509::X509::from_der(cert_bytes.as_slice())?.to_pem()?;
        Ok(Pem::try_from(cert.as_slice())?)
    }


//----------------------------------------------------------
//       Public helper functions: Everything asymmetric
//----------------------------------------------------------


    pub fn is_rsa_key_algorithm(algorithm: &ObjectAlgorithm) -> bool {
        MgmAlgorithm::RSA_KEY_ALGORITHMS.iter().any(|a| a.algorithm() == *algorithm)
    }

    pub fn is_ec_key_algorithm(algorithm: &ObjectAlgorithm) -> bool {
        MgmAlgorithm::EC_KEY_ALGORITHMS.iter().any(|a| a.algorithm() == *algorithm)
    }

    pub fn is_oaep_algorithm(algorithm: &ObjectAlgorithm) -> bool {
        MgmAlgorithm::RSA_OAEP_ALGORITHMS.iter().any(|a| a.algorithm() == *algorithm)
    }

    pub fn get_hashed_bytes(algo: &ObjectAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
        match algo {
            ObjectAlgorithm::RsaPkcs1Sha1 | ObjectAlgorithm::RsaPssSha1 | ObjectAlgorithm::EcdsaSha1 | ObjectAlgorithm::RsaOaepSha1 => Ok(openssl::hash::hash(MessageDigest::sha1(), input)?.to_vec()),
            ObjectAlgorithm::RsaPkcs1Sha256 | ObjectAlgorithm::RsaPssSha256 | ObjectAlgorithm::EcdsaSha256 | ObjectAlgorithm::RsaOaepSha256 => Ok(openssl::hash::hash(MessageDigest::sha256(), input)?.to_vec()),
            ObjectAlgorithm::RsaPkcs1Sha384 | ObjectAlgorithm::RsaPssSha384 | ObjectAlgorithm::EcdsaSha384 | ObjectAlgorithm::RsaOaepSha384 => Ok(openssl::hash::hash(MessageDigest::sha384(), input)?.to_vec()),
            ObjectAlgorithm::RsaPkcs1Sha512 | ObjectAlgorithm::RsaPssSha512 | ObjectAlgorithm::EcdsaSha512 | ObjectAlgorithm::RsaOaepSha512 => Ok(openssl::hash::hash(MessageDigest::sha512(), input)?.to_vec()),
            _ => Err(MgmError::InvalidInput("Algorithm does not contain hash component".to_string()))
        }
    }

    pub fn get_mgf1_algorithm(algo: &ObjectAlgorithm) -> Result<ObjectAlgorithm, MgmError> {
        match algo {
            ObjectAlgorithm::RsaOaepSha1 | ObjectAlgorithm::RsaPssSha1 => Ok(ObjectAlgorithm::Mgf1Sha1),
            ObjectAlgorithm::RsaOaepSha256 | ObjectAlgorithm::RsaPssSha256 => Ok(ObjectAlgorithm::Mgf1Sha256),
            ObjectAlgorithm::RsaOaepSha384 | ObjectAlgorithm::RsaPssSha384 => Ok(ObjectAlgorithm::Mgf1Sha384),
            ObjectAlgorithm::RsaOaepSha512 | ObjectAlgorithm::RsaPssSha512 => Ok(ObjectAlgorithm::Mgf1Sha512),
            _ => Err(MgmError::InvalidInput("Algorithm is not an RSA PSS or OAEP decryption algorithm".to_string())),
        }
    }

    pub fn parse_asym_pem(pem: Pem) -> Result<(ObjectType, ObjectAlgorithm, Vec<u8>), MgmError> {
        let bytes = pem.contents();
        if bytes.is_empty() {
            return Err(MgmError::InvalidInput("DER data is empty".to_string()));
        }
        if let Ok(privkey) = openssl::pkey::PKey::private_key_from_der(bytes) {
            return match privkey.id() {
                pkey::Id::RSA => {
                    let private_rsa = privkey.rsa()?;
                    let key_algorithm = Self::get_rsa_key_algo(private_rsa.size())?;

                    let Some(p) = private_rsa.p() else {
                        return Err(MgmError::InvalidInput("Failed to read p value".to_string()));
                    };
                    let Some(q) = private_rsa.q() else {
                        return Err(MgmError::InvalidInput("Failed to read q value".to_string()));
                    };

                    let mut key_bytes = p.to_vec();
                    key_bytes.extend_from_slice(&q.to_vec());
                    Ok((ObjectType::AsymmetricKey, key_algorithm, key_bytes))
                }
                pkey::Id::EC => {
                    let private_ec = privkey.ec_key()?;
                    let s = private_ec.private_key();
                    let group = private_ec.group();
                    let Some(nid) = group.curve_name() else {
                        return Err(MgmError::InvalidInput("Failed to read EC curve name".to_string()))
                    };

                    let key_algorithm = Self::get_algo_from_nid(nid)?;
                    Ok((ObjectType::AsymmetricKey, key_algorithm, s.to_vec()))
                }
                pkey::Id::ED25519 => {
                    let private_ed = PKey::private_key_from_raw_bytes(bytes, pkey::Id::ED25519)?;
                    let k = private_ed.raw_private_key()?;
                    Ok((ObjectType::AsymmetricKey, ObjectAlgorithm::Ed25519, k.to_vec()))
                }
                _ => Err(MgmError::InvalidInput("Unknown or unsupported key type".to_string())),
            }
        }

        if let Ok(pubkey) = openssl::pkey::PKey::public_key_from_der(bytes) {
            return match pubkey.id() {
                pkey::Id::RSA => {
                    let public_rsa = pubkey.rsa()?;
                    let n = public_rsa.n();
                    // let e = public_rsa.e();

                    let key_bytes = n.to_vec();
                    // key_bytes.extend_from_slice(&e.to_vec());
                    let key_algorithm = Self::get_rsa_key_algo(public_rsa.size())?;
                    Ok((ObjectType::PublicKey, key_algorithm, key_bytes))
                }
                pkey::Id::EC => {
                    let public_ec = pubkey.ec_key()?;
                    let group = public_ec.group();
                    let point = public_ec.public_key();
                    let mut ctx = BigNumContext::new()?;
                    let pubkey_bytes = point.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

                    let Some(nid) = group.curve_name() else {
                        return Err(MgmError::InvalidInput("Failed to read EC curve name".to_string()))
                    };

                    let key_algorithm = Self::get_algo_from_nid(nid)?;
                    Ok((ObjectType::PublicKey, key_algorithm, pubkey_bytes.to_vec()))
                }
                pkey::Id::ED25519 => {
                    let public_ed = PKey::public_key_from_raw_bytes(bytes, pkey::Id::ED25519)?;
                    let k = public_ed.raw_public_key()?;
                    Ok((ObjectType::PublicKey, ObjectAlgorithm::Ed25519, k.to_vec()))
                }
                _ => Err(MgmError::InvalidInput("Unknown or unsupported key type".to_string())),
            }
        }

        if openssl::x509::X509::from_der(bytes).is_ok() {
            return Ok((ObjectType::Opaque, ObjectAlgorithm::OpaqueX509Certificate, bytes.to_vec()))
        }

        Err(MgmError::InvalidInput("Failed to parse PEM data as either private key, public key or X509Certificate".to_string()))
    }


//----------------------------------------------------------
//       Internal helper functions
//----------------------------------------------------------


    fn get_rsa_key_algo(size_in_bytes: u32) -> Result<ObjectAlgorithm, MgmError> {
        match size_in_bytes {
            256 => Ok(ObjectAlgorithm::Rsa2048),
            384 => Ok(ObjectAlgorithm::Rsa3072),
            512 => Ok(ObjectAlgorithm::Rsa4096),
            _ => {
                Err(MgmError::Error(format!("Unsupported RSA key size {}", (size_in_bytes * 8))))
            }
        }
    }

    fn get_algo_from_nid(nid: Nid) -> Result<ObjectAlgorithm, MgmError> {
        match nid {
            Nid::X9_62_PRIME256V1 => Ok(ObjectAlgorithm::EcP256),
            Nid::SECP256K1 => Ok(ObjectAlgorithm::EcK256),
            Nid::SECP384R1 => Ok(ObjectAlgorithm::EcP384),
            Nid::SECP521R1 => Ok(ObjectAlgorithm::EcP521),
            Nid::SECP224R1 => Ok(ObjectAlgorithm::EcP224),
            Nid::BRAINPOOL_P256R1 => Ok(ObjectAlgorithm::EcBp256),
            Nid::BRAINPOOL_P384R1 => Ok(ObjectAlgorithm::EcBp384),
            Nid::BRAINPOOL_P512R1 => Ok(ObjectAlgorithm::EcBp512),
            _ => {
                Err(MgmError::InvalidInput(format!("Unsupported EC curve {:?}", nid)))
            }
        }
    }

    fn import_attestation_template(session: &Session, attesting_key: u16, attested_key: u16, template_cert: Option<Pem>) -> Result<bool, MgmError> {
        match session.get_object_info(attesting_key, ObjectType::Opaque) {
            Ok(opaque) => {
                if template_cert.is_some() || opaque.algorithm != ObjectAlgorithm::OpaqueX509Certificate {
                    return Err(MgmError::Error("An opaque object with the same ID as the attesting key already exists on the device".to_string()))
                }
                Ok(false)
            },
            Err(_) => {
                if template_cert.is_some() {
                    let (_, algo, der_bytes) = Self::parse_asym_pem(template_cert.unwrap())?;
                    if algo != ObjectAlgorithm::OpaqueX509Certificate {
                        return Err(MgmError::InvalidInput("Attestation template is not an X509Certificate".to_string()));
                    }
                    session.import_cert(attesting_key, "template_cert", &ObjectDomain::from_primitive(0xFFFF), &Vec::new(), &der_bytes)?;
                } else {
                    let template_cert = session.sign_attestation_certificate(attested_key, 0)?;
                    session.import_cert(attesting_key, "template_cert", &ObjectDomain::from_primitive(0xFFFF), &Vec::new(), template_cert.as_slice())?;
                }
                Ok(true)
            }
        }
    }
}


//----------------------------------------------------------
//       JAVA Special case
//----------------------------------------------------------

pub struct JavaOps;

impl Obtainable for JavaOps {
    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut keys = session.list_objects_with_filter(
            0,
            ObjectType::Opaque,
            "",
            ObjectAlgorithm::OpaqueX509Certificate,
            &Vec::new())?;
        keys.retain(|k| session.get_object_info(k.object_id, ObjectType::AsymmetricKey).is_ok());
        keys.iter_mut().for_each(|x| x.object_type = ObjectType::AsymmetricKey);
        let mut keys = get_descriptors_from_handlers(session, &keys)?;
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)    }

    fn get_object_algorithms() -> Vec<MgmAlgorithm> {
        AsymOps::get_object_algorithms()
    }

    fn get_object_capabilities(object_algorithm: &ObjectAlgorithm) -> Vec<ObjectCapability> {
        AsymOps::get_object_capabilities(object_algorithm)
    }
}

impl Deletable for JavaOps {
    fn delete(&self, session: &Session, object_id: u16, _: ObjectType) -> Result<(), MgmError> {
        session.delete_object(object_id, ObjectType::AsymmetricKey)?;
        session.delete_object(object_id, ObjectType::Opaque)?;
        Ok(())
    }
}

impl Generatable for JavaOps {
    fn generate(&self, session: &Session, spec: &ObjectSpec) -> Result<u16, MgmError> {
        Self::check_free_id(session, spec.id)?;

        let key_id = if spec.id != 0 {
            AsymOps.generate(session, spec)?
        } else {
            let mut id;
            loop {
                id = AsymOps.generate(session, spec)?;
                if session.get_object_info(id, ObjectType::Opaque).is_err() {
                    break;
                }
                session.delete_object(id, ObjectType::AsymmetricKey)?;
            }
            id
        };

        let cert = session.sign_attestation_certificate(key_id, 0);
        let cert = match cert {
            Ok(c) => c,
            Err(e) => {
                session.delete_object(key_id, ObjectType::AsymmetricKey)?;
                return Err(MgmError::from(e))
            }
        };

        let cert_capabilities =
            if spec.capabilities.contains(&ObjectCapability::ExportableUnderWrap) {
                vec![ObjectCapability::ExportableUnderWrap]
            } else {
                vec![]
            };

        let res = session.import_cert(
            key_id,
            spec.label.as_str(),
            spec.domains.as_slice(),
            cert_capabilities.as_slice(),
            cert.as_slice());

        match res {
            Ok(_) => Ok(key_id),
            Err(e) => {
                session.delete_object(key_id, ObjectType::AsymmetricKey)?;
                Err(MgmError::from(e))
            }
        }
    }
}

impl Importable for JavaOps {
    fn import(&self, session: &Session, spec: &ImportObjectSpec) -> Result<u16, MgmError> {
        Self::check_free_id(session, spec.object.id)?;

        let key_id = if spec.object.id != 0 {
            AsymOps.import(session, spec)?
        } else {
            let mut id;
            loop {
                id = AsymOps.import(session, spec)?;
                if session.get_object_info(id, ObjectType::Opaque).is_err() {
                    break;
                }
                session.delete_object(id, ObjectType::AsymmetricKey)?;
            }
            id
        };

        let cert_capabilities =
            if spec.object.capabilities.contains(&ObjectCapability::ExportableUnderWrap) {
                vec![ObjectCapability::ExportableUnderWrap]
            } else {
                vec![]
            };

        let res = session.import_cert(
            key_id,
            spec.object.label.as_str(),
            spec.object.domains.as_slice(),
            cert_capabilities.as_slice(),
            spec.data[1].as_slice());

        match res {
            Ok(_) => Ok(key_id),
            Err(e) => {
                session.delete_object(key_id, ObjectType::AsymmetricKey)?;
                Err(MgmError::from(e))
            }
        }
    }
}


impl JavaOps {

    const JAVA_COMMANDS: [CommandSpec;6] = [
        CommandSpec {
            command: YhCommand::List,
            label: "List",
            description: "List all SunPKCS11 compatible keys where an asymmetric key and an X509Certificate objects have the same Object ID in the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        CommandSpec {
            command: YhCommand::Generate,
            label: "Generate",
            description: "Generate a new asymmetric key and an attestation certificate and stores them using the same Object ID inside the YubiHSM",
            required_capabilities: &[ObjectCapability::GenerateAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate],
            require_all_capabilities: true,
        },
        CommandSpec {
            command: YhCommand::Import,
            label: "Import",
            description: "Import an asymmetric key and X509 certificate and stores then using the same Object ID on the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque],
            require_all_capabilities: true,
        },
        CommandSpec {
            command: YhCommand::Delete,
            label: "Delete",
            description: "Delete an asymmetric key and X509 certificate with the same Object ID from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteAsymmetricKey, ObjectCapability::DeleteOpaque],
            require_all_capabilities: true,
        },
        CommandSpec::RETURN_COMMAND,
        CommandSpec::EXIT_COMMAND,
    ];

    pub fn get_authorized_commands(
        authkey: &ObjectDescriptor,
    ) -> Vec<CommandSpec> {
        get_authorized_commands(authkey, &Self::JAVA_COMMANDS)
    }

    fn check_free_id(session: &Session, id: u16) -> Result<(), MgmError> {
        if id != 0 && (session.get_object_info(id, ObjectType::AsymmetricKey).is_ok() || session.get_object_info(id, ObjectType::Opaque).is_ok()) {
            return Err(MgmError::Error("Object ID already in use".to_string()));
        }
        Ok(())
    }
}
