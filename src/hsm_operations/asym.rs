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
use crate::traits::operation_traits::{YubihsmOperations};
use crate::hsm_operations::error::MgmError;
use crate::hsm_operations::algorithms::MgmAlgorithm;
use crate::hsm_operations::common::{get_op_keys, get_object_descriptors};
use crate::hsm_operations::types::{MgmCommand, NewObjectSpec, MgmCommandType};

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

pub struct AsymmetricOperations;

impl YubihsmOperations for AsymmetricOperations {
    fn get_commands(&self) -> Vec<MgmCommand> {
        [
            MgmCommand {
                command: MgmCommandType::List,
                label: "List",
                description: "List all asymmetric keys and X509 certificates stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false
            },
            MgmCommand {
                command: MgmCommandType::GetKeyProperties,
                label: "Get Object Properties",
                description: "Get properties of an asymmetric key or X509 certificate stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Generate,
                label: "Generate",
                description: "Generate a new asymmetric key inside the YubiHSM",
                required_capabilities: &[ObjectCapability::GenerateAsymmetricKey],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Import,
                label: "Import",
                description: "Import an asymmetric key or X509 certificate into the YubiHSM",
                required_capabilities: &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Delete,
                label: "Delete",
                description: "Delete an asymmetric key or X509 certificate from the YubiHSM",
                required_capabilities: &[ObjectCapability::DeleteAsymmetricKey,
                    ObjectCapability::DeleteOpaque],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::GetPublicKey,
                label: "Get Public Key",
                description: "Retrieve the public key portion of an asymmetric key stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::GetCertificate,
                label: "Get X509 Certificate",
                description: "Retrieve an X509 certificate stored on the YubiHSM",
                required_capabilities: &[],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Sign,
                label: "Sign",
                description: "Sign data using an asymmetric private key stored on the YubiHSM",
                required_capabilities: &[ObjectCapability::SignPkcs,
                    ObjectCapability::SignPss,
                    ObjectCapability::SignEcdsa,
                    ObjectCapability::SignEddsa],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::Decrypt,
                label: "Decrypt",
                description: "Decrypt data using an asymmetric private key stored on the YubiHSM",
                required_capabilities: &[ObjectCapability::DecryptPkcs,
                    ObjectCapability::DecryptOaep],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::DeriveEcdh,
                label: "Derive ECDH",
                description: "Derive an ECDH shared secret using an EC private key stored on the YubiHSM",
                required_capabilities: &[ObjectCapability::DeriveEcdh],
                require_all_capabilities: false,
            },
            MgmCommand {
                command: MgmCommandType::SignAttestationCert,
                label: "Sign Attestation Certificate",
                description: "Generate and sign an attestation certificate for a key generated on the YubiHSM",
                required_capabilities: &[ObjectCapability::SignAttestationCertificate],
                require_all_capabilities: false,
            },
            MgmCommand::EXIT_COMMAND].to_vec()
    }

    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        Self::get_asymmetric_objects(session, &[ObjectType::AsymmetricKey, ObjectType::Opaque])
    }

    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm> {
        let mut algos = MgmAlgorithm::RSA_KEY_ALGORITHMS.to_vec();
        algos.extend(MgmAlgorithm::EC_KEY_ALGORITHMS.to_vec());
        algos.extend(MgmAlgorithm::ED_KEY_ALGORITHMS.to_vec());
        algos
    }

    fn get_object_capabilities(&self, _: Option<ObjectType>, object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        let algo = if let Some(a) = object_algorithm {
            a
        } else {
            return Err(MgmError::InvalidInput("Missing asymmetric object algorithm".to_string()));
        };
        let caps = if Self::is_rsa_key_algorithm(&algo) {
            Self::RSA_KEY_CAPABILITIES.to_vec()
        } else if Self::is_ec_key_algorithm(&algo) {
            Self::EC_KEY_CAPABILITIES.to_vec()
        } else if algo == ObjectAlgorithm::Ed25519 {
            Self::ED_KEY_CAPABILITIES.to_vec()
        } else if algo == ObjectAlgorithm::OpaqueX509Certificate {
            Self::OPAQUE_CAPABILITIES.to_vec()
        } else {
            return Err(MgmError::InvalidInput(
                format!("Unsupported asymmetric object algorithm {:?}", object_algorithm)));
        };
        Ok(caps)
    }

    fn generate(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        let key = session
            .generate_asymmetric_key_with_keyid(
                spec.id, &spec.label, &spec.capabilities, &spec.domains, spec.algorithm)?;
        Ok(key.get_key_id())
    }

    fn import(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        let key_data = &spec.data[0];
        let id =
            if Self::is_rsa_key_algorithm(&spec.algorithm) {
                session.import_rsa_key(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    spec.algorithm,
                    &key_data[0..key_data.len() / 2],
                    &key_data[key_data.len() / 2..])?
            } else if Self::is_ec_key_algorithm(&spec.algorithm) {
                session.import_ec_key(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    spec.algorithm,
                    key_data)?
            } else if spec.algorithm == ObjectAlgorithm::Ed25519 {
                session.import_ed_key(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    key_data)?
            } else if spec.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
                session.import_cert(
                    spec.id,
                    &spec.label,
                    &spec.domains,
                    &spec.capabilities,
                    key_data)?
            } else {
                return Err(MgmError::InvalidInput(
                    format!("Unsupported asymmetric key algorithm {:?}", spec.algorithm)));
            };
        Ok(id)
    }
}

impl AsymmetricOperations {

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

    const ED_KEY_CAPABILITIES: [ObjectCapability; 2] = [
        ObjectCapability::SignEddsa,
        ObjectCapability::ExportableUnderWrap];

    const OPAQUE_CAPABILITIES: [ObjectCapability; 1] = [
        ObjectCapability::ExportableUnderWrap];


//----------------------------------------------------------
//       Main symmetric functions requiring a session
// ----------------------------------------------------------
    pub fn get_asymmetric_objects(session: &Session, types: &[ObjectType]) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let mut objects = Vec::new();
        if types.contains(&ObjectType::Opaque) {
            objects.extend(session.list_objects_with_filter(0, ObjectType::Opaque, "", ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
        }
        if types.contains(&ObjectType::AsymmetricKey) {
            objects.extend(session.list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?);
        }
        get_object_descriptors(session, &objects)
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
                algos.push(ObjectAlgorithm::RsaPkcs1Decrypt.into());
            }
            if deckey.capabilities.contains(&ObjectCapability::DecryptOaep) && authkey.capabilities.contains(&ObjectCapability::DecryptOaep) {
                algos.extend_from_slice(&MgmAlgorithm::RSA_OAEP_ALGORITHMS);
            }
        }
        algos
    }

    pub fn get_pubkey(session: &Session, object_id: u16, object_typ: ObjectType) -> Result<Pem, MgmError> {
        let (pubkey, algo) = session.get_pubkey(object_id, object_typ)?;
        Self::get_pubkey_pem(algo, pubkey.as_slice())
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
            let oaep_label: &[u8] = &[];
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

    pub fn get_pubkey_pem(algorithm: ObjectAlgorithm, pubkey_bytes: &[u8]) -> Result<Pem, MgmError> {
        let pem_bytes: Vec<u8> = if Self::is_rsa_key_algorithm(&algorithm) {
            let e = BigNum::from_slice(&[0x01, 0x00, 0x01])?;
            let n = BigNum::from_slice(pubkey_bytes)?;
            let rsa_pubkey = openssl::rsa::Rsa::from_public_components(n, e)?;
            rsa_pubkey.public_key_to_pem()?
        } else if Self::is_ec_key_algorithm(&algorithm) {
            let nid = match algorithm {
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
            if pubkey_bytes[0] != 0x04 {
                ec_pubkey_bytes.push(0x04);
            }
            ec_pubkey_bytes.extend(pubkey_bytes);
            let ec_point = EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx)?;
            let ec_pubkey = EcKey::from_public_key(&ec_group, &ec_point)?;
            ec_pubkey.public_key_to_pem()?
        } else if algorithm == ObjectAlgorithm::Ed25519 {
            let ed_pubkey = PKey::public_key_from_raw_bytes(pubkey_bytes, pkey::Id::ED25519)?;
            ed_pubkey.public_key_to_pem()?
        } else {
            return Err(MgmError::InvalidInput(
                format!("Unknown or unsupported asymmetric key algorithm {:?}", algorithm)));
        };
        let pem = Pem::try_from(pem_bytes.as_slice())?;
        Ok(pem)
    }
    //
    // pub fn parse_subject_dn_string(dn_string: &str) -> Result<X509Name, MgmError> {
    //     // Ex: "CN=Test,O=Example,C=US"
    //
    //     let mut builder = X509NameBuilder::new()?;
    //
    //     // Split by comma, but be careful with escaped commas
    //     for component in dn_string.split(',') {
    //         let component = component.trim();
    //
    //         // Split by '=' to get key and value
    //         if let Some((key, value)) = component.split_once('=') {
    //             let key = key.trim();
    //             let value = value.trim();
    //             builder.append_entry_by_text(key, value)?;
    //         } else {
    //             return Err(MgmError::InvalidInput(format!("Invalid DN component: {}", component)));
    //         }
    //     }
    //
    //     Ok(builder.build())
    // }


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

impl YubihsmOperations for JavaOps {
    fn get_commands(&self) -> Vec<MgmCommand> {
        Self::JAVA_COMMANDS.to_vec()
    }

    fn get_all_objects(&self, session: &Session) -> Result<Vec<ObjectDescriptor>, MgmError> {
        let certs = session.list_objects_with_filter(
            0,
            ObjectType::Opaque,
            "",
            ObjectAlgorithm::OpaqueX509Certificate,
            &Vec::new())?;

        let mut keys = Vec::new();
        for c in &certs {
            if let Ok(desc) = session.get_object_info(c.object_id, ObjectType::AsymmetricKey) {
                keys.push(desc);
            }
        }
        Ok(keys)
    }

    fn get_generation_algorithms(&self) -> Vec<MgmAlgorithm> {
        AsymmetricOperations.get_generation_algorithms()
    }

    fn get_object_capabilities(&self, _object_type: Option<ObjectType>, object_algorithm: Option<ObjectAlgorithm>) -> Result<Vec<ObjectCapability>, MgmError> {
        AsymmetricOperations.get_object_capabilities(_object_type, object_algorithm)
    }

    fn generate(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        Self::check_free_id(session, spec.id)?;

        let key_id = if spec.id != 0 {
            AsymmetricOperations.generate(session, spec)?
        } else {
            let mut id;
            loop {
                id = AsymmetricOperations.generate(session, spec)?;
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

    fn import(&self, session: &Session, spec: &NewObjectSpec) -> Result<u16, MgmError> {
        Self::check_free_id(session, spec.id)?;

        let key_id = if spec.id != 0 {
            AsymmetricOperations.import(session, spec)?
        } else {
            let mut id;
            loop {
                id = AsymmetricOperations.import(session, spec)?;
                if session.get_object_info(id, ObjectType::Opaque).is_err() {
                    break;
                }
                session.delete_object(id, ObjectType::AsymmetricKey)?;
            }
            id
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
            spec.data[1].as_slice());

        match res {
            Ok(_) => Ok(key_id),
            Err(e) => {
                session.delete_object(key_id, ObjectType::AsymmetricKey)?;
                Err(MgmError::from(e))
            }
        }    }

    fn delete(&self, session: &Session, object_id: u16, _object_type: ObjectType) -> Result<(), MgmError> {
        session.delete_object(object_id, ObjectType::AsymmetricKey)?;
        session.delete_object(object_id, ObjectType::Opaque)?;
        Ok(())
    }
}

impl JavaOps {

    const JAVA_COMMANDS: [MgmCommand;6] = [
        MgmCommand {
            command: MgmCommandType::List,
            label: "List",
            description: "List all SunPKCS11 compatible keys where an asymmetric key and an X509Certificate objects have the same Object ID on the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false
        },
        MgmCommand {
            command: MgmCommandType::GetKeyProperties,
            label: "Get Object Properties",
            description: "Get properties of a SunPKCS11 compatible asymmetric key stored on the YubiHSM",
            required_capabilities: &[],
            require_all_capabilities: false,
        },
        MgmCommand {
            command: MgmCommandType::Generate,
            label: "Generate",
            description: "Generate a new asymmetric key and an attestation certificate and stores them using the same Object ID inside the YubiHSM",
            required_capabilities: &[ObjectCapability::GenerateAsymmetricKey, ObjectCapability::PutOpaque, ObjectCapability::SignAttestationCertificate],
            require_all_capabilities: true,
        },
        MgmCommand {
            command: MgmCommandType::Import,
            label: "Import",
            description: "Import an asymmetric key and X509 certificate and stores then using the same Object ID on the YubiHSM",
            required_capabilities: &[ObjectCapability::PutAsymmetricKey, ObjectCapability::PutOpaque],
            require_all_capabilities: true,
        },
        MgmCommand {
            command: MgmCommandType::Delete,
            label: "Delete",
            description: "Delete an asymmetric key and X509 certificate with the same Object ID from the YubiHSM",
            required_capabilities: &[ObjectCapability::DeleteAsymmetricKey, ObjectCapability::DeleteOpaque],
            require_all_capabilities: true,
        },
        MgmCommand::EXIT_COMMAND,
    ];

    fn check_free_id(session: &Session, id: u16) -> Result<(), MgmError> {
        if id != 0 && (session.get_object_info(id, ObjectType::AsymmetricKey).is_ok() || session.get_object_info(id, ObjectType::Opaque).is_ok()) {
            return Err(MgmError::Error("Object ID already in use".to_string()));
        }
        Ok(())
    }
}
