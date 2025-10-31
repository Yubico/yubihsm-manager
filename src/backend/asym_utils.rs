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
use pem::Pem;
use openssl::pkey;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hash::{MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;

use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectHandle, ObjectType};
use yubihsmrs::Session;
use crate::error::MgmError;

pub const RSA_KEY_CAPABILITIES: [ObjectCapability; 6] = [
    ObjectCapability::SignPkcs,
    ObjectCapability::SignPss,
    ObjectCapability::DecryptPkcs,
    ObjectCapability::DecryptOaep,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

pub const EC_KEY_CAPABILITIES: [ObjectCapability; 4] = [
    ObjectCapability::SignEcdsa,
    ObjectCapability::DeriveEcdh,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

pub const ED_KEY_CAPABILITIES: [ObjectCapability; 3] = [
    ObjectCapability::SignEddsa,
    ObjectCapability::ExportableUnderWrap,
    ObjectCapability::SignAttestationCertificate];

pub const OPAQUE_CAPABILITIES: [ObjectCapability; 1] = [
    ObjectCapability::ExportableUnderWrap];

pub const RSA_KEY_ALGORITHM: [ObjectAlgorithm; 3] = [
    ObjectAlgorithm::Rsa2048,
    ObjectAlgorithm::Rsa3072,
    ObjectAlgorithm::Rsa4096];

pub const EC_KEY_ALGORITHM: [ObjectAlgorithm; 8] = [
    ObjectAlgorithm::EcP224,
    ObjectAlgorithm::EcP256,
    ObjectAlgorithm::EcP384,
    ObjectAlgorithm::EcP521,
    ObjectAlgorithm::EcK256,
    ObjectAlgorithm::EcBp256,
    ObjectAlgorithm::EcBp384,
    ObjectAlgorithm::EcBp512];

pub const RSA_OAEP_ALGORITHM: [ObjectAlgorithm; 4] = [
    ObjectAlgorithm::RsaOaepSha1,
    ObjectAlgorithm::RsaOaepSha256,
    ObjectAlgorithm::RsaOaepSha384,
    ObjectAlgorithm::RsaOaepSha512];

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AsymTypes {
    #[default]
    Keys,
    X509Certificates,
}

impl Display for AsymTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsymTypes::Keys => write!(f, "Private keys"),
            AsymTypes::X509Certificates => write!(f, "X509Certificates"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq,  Eq, Default)]
pub enum AttestationTypes {
    #[default]
    DeviceSigned,
    SelfSigned,
    AsymSigned,
}

impl Display for AttestationTypes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttestationTypes::DeviceSigned => write!(f, "Signed by device attestation key"),
            AttestationTypes::SelfSigned => write!(f, "Self signed"),
            AttestationTypes::AsymSigned => write!(f, "Signed by another asymmetric key"),
        }
    }
}

pub fn get_asymmetric_objects(session: &Session, types:&[AsymTypes]) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = Vec::new();
    if types.contains(&AsymTypes::Keys) {
        keys.extend(session.
                               list_objects_with_filter(0, ObjectType::AsymmetricKey, "", ObjectAlgorithm::ANY, &Vec::new())?);
    }
    if types.contains(&AsymTypes::X509Certificates) {
        keys.extend(session.
                               list_objects_with_filter(0, ObjectType::Opaque, "",ObjectAlgorithm::OpaqueX509Certificate, &Vec::new())?);
    }
    Ok(keys)
}

pub fn generate_asym_key(session: &Session, new_key:&ObjectDescriptor) -> Result<u16, MgmError> {
    let key = session
        .generate_asymmetric_key_with_keyid(
            new_key.id, &new_key.label, &new_key.capabilities, &new_key.domains, new_key.algorithm)?;
    Ok(key.get_key_id())
}

pub fn import_asym_object(session: &Session, new_object: &mut ObjectDescriptor, object_bytes:&[u8]) -> Result<(), MgmError> {
    if RSA_KEY_ALGORITHM.contains(&new_object.algorithm) {
        new_object.id = session.import_rsa_key(
            new_object.id,
            &new_object.label,
            &new_object.domains,
            &new_object.capabilities,
            new_object.algorithm,
            &object_bytes[0..object_bytes.len() / 2],
            &object_bytes[object_bytes.len() / 2..])?;
    } else if EC_KEY_ALGORITHM.contains(&new_object.algorithm) {
        new_object.id = session.import_ec_key(
            new_object.id,
            &new_object.label,
            &new_object.domains,
            &new_object.capabilities,
            new_object.algorithm,
            &object_bytes.to_vec())?;
    } else if new_object.algorithm == ObjectAlgorithm::Ed25519 {
        new_object.id = session.import_ed_key(
            new_object.id,
            &new_object.label,
            &new_object.domains,
            &new_object.capabilities,
            &object_bytes.to_vec())?;
    } else if new_object.algorithm == ObjectAlgorithm::OpaqueX509Certificate {
        new_object.id = session.import_cert(
            new_object.id,
            &new_object.label,
            &new_object.domains,
            &new_object.capabilities,
            object_bytes)?;
    } else {
        return Err(MgmError::InvalidInput(
            format!("Unsupported asymmetric key algorithm {:?}", new_object.algorithm)));
    }

    Ok(())
}

pub fn get_public_key(session:&Session, key_id:u16, key_typ:ObjectType) -> Result<(Vec<u8>, ObjectAlgorithm), MgmError> {
    match session.get_pubkey(key_id, key_typ) {
        Ok(pk) => Ok(pk),
        Err(e) => Err(MgmError::LibYubiHsm(e))
    }
}

pub fn get_certificate(session:&Session, key_id:u16) -> Result<Vec<u8>, MgmError> {
    let data = session.get_opaque(key_id)?;
    match openssl::x509::X509::from_der(data.as_slice())  {
        Ok(cert) => Ok(cert.to_pem()?),
        Err(_) => Err(MgmError::InvalidInput(format!("Opaque object 0x{:04x} is not an X509Certificate", key_id)))
    }
}

pub fn sign(session:&Session, sign_key:&ObjectDescriptor, sign_algorithm:&ObjectAlgorithm, data:&[u8]) -> Result<Vec<u8>, MgmError> {
    let sig =
    if RSA_KEY_ALGORITHM.contains(&sign_key.algorithm) {
        let hashed_bytes = get_hashed_bytes(sign_algorithm, data)?;
        if [ObjectAlgorithm::RsaPkcs1Sha1, ObjectAlgorithm::RsaPkcs1Sha256,
            ObjectAlgorithm::RsaPkcs1Sha384, ObjectAlgorithm::RsaPkcs1Sha512].contains(&sign_algorithm) {
            session.sign_pkcs1v1_5(sign_key.id, true, hashed_bytes.as_slice())?
        } else {
            let mgf1_algo = get_mgf1_algorithm(sign_algorithm)?;
            session.sign_pss(sign_key.id, hashed_bytes.len(), mgf1_algo, hashed_bytes.as_slice())?
        }
    } else if EC_KEY_ALGORITHM.contains(&sign_key.algorithm) {
            let hashed_bytes = get_hashed_bytes(&sign_algorithm, data)?;
            session.sign_ecdsa(sign_key.id, hashed_bytes.as_slice())?
    } else if sign_key.algorithm == ObjectAlgorithm::Ed25519 {
            session.sign_eddsa(sign_key.id, data)?
    } else {
        return Err(MgmError::Error("Selected key has no asymmetric signing capabilities".to_string()))
    };
    Ok(sig)
}

pub fn decrypt(session:&Session, dec_key:&ObjectDescriptor, dec_algorithm:&ObjectAlgorithm, oaep_label:String, ciphertext:&[u8]) -> Result<Vec<u8>, MgmError> {
    let plaintext =
        if dec_algorithm == &ObjectAlgorithm::RsaPkcs1Decrypt {
            session.decrypt_pkcs1v1_5(dec_key.id, ciphertext)?
        } else if RSA_OAEP_ALGORITHM.contains(&dec_algorithm) {
            let label = if oaep_label.is_empty() {Vec::new()} else {hex::decode(oaep_label)?};
            let label = get_hashed_bytes(dec_algorithm, label.as_slice())?;
            let mgf1_algo = get_mgf1_algorithm(dec_algorithm)?;
            session.decrypt_oaep(dec_key.id, ciphertext, label.as_slice(), mgf1_algo)?
        } else {
            return Err(MgmError::InvalidInput("Selected decryption algorithm is not supported".to_string()))
        };
    Ok(plaintext)
}

pub fn derive_ecdh(session:&Session, hsm_key:&ObjectDescriptor, peer_pubkey:Pem) -> Result<Vec<u8>, MgmError> {
    let (peer_type, peer_algo, peer_key) = get_asym_object_from_der(peer_pubkey.contents())?;

    if peer_type != ObjectType::PublicKey {
        return Err(MgmError::InvalidInput("Peer public key is not a public key".to_string()))
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
    template_cert_der:&[u8]) -> Result<Vec<u8>, MgmError> {

    let cert_bytes =
        if attesting_key == 0 {
            session.sign_attestation_certificate(attested_key, 0)?
        } else {
            let imported_template =  import_attestation_template(session, attesting_key, template_cert_der)?;
            let cert = session.sign_attestation_certificate(attested_key, attesting_key)?;
            if imported_template {
                session.delete_object(attesting_key, ObjectType::Opaque)?;
            }
            cert
        };
    Ok(openssl::x509::X509::from_der(cert_bytes.as_slice())?.to_pem()?)
}

pub fn java_get_keys(session: &Session) -> Result<Vec<ObjectHandle>, MgmError> {
    let mut keys = session.list_objects_with_filter(
        0,
        ObjectType::Opaque,
        "",
        ObjectAlgorithm::OpaqueX509Certificate,
        &Vec::new())?;
    keys.retain(|k| session.get_object_info(k.object_id, ObjectType::AsymmetricKey).is_ok());
    keys.iter_mut().for_each(|x| x.object_type = ObjectType::AsymmetricKey);
    Ok(keys)
}

pub fn java_generate_key(session:&Session, new_key:&ObjectDescriptor) -> Result<u16, MgmError> {
    let mut key = new_key.clone();

    if key.id != 0 {
        key.id = generate_asym_key(session, &key)?;
    } else {
        loop {
            let key_id = generate_asym_key(session, &key)?;
            if session.get_object_info(key.id, ObjectType::Opaque).is_err() {
                key.id = key_id;
                break;
            }
            session.delete_object(key_id, ObjectType::AsymmetricKey)?;
        }
    }

    let cert = get_attestation_cert(session, key.id, 0, &[]);
    let cert = match cert {
        Ok(c) => c,
        Err(e) => {
            session.delete_object(key.id, ObjectType::AsymmetricKey)?;
            return Err(e)
        }
    };

    let cert_capabilities =
        if key.capabilities.contains(&ObjectCapability::ExportableUnderWrap) {
            vec![ObjectCapability::ExportableUnderWrap]
        } else {
            vec![]
        };
    let res = session.import_cert(
        key.id,
        key.label.as_str(),
        key.domains.as_slice(),
        cert_capabilities.as_slice(),
        cert.as_slice());

    match res {
        Ok(_) => Ok(key.id),
        Err(e) => {
            session.delete_object(key.id, ObjectType::AsymmetricKey)?;
            Err(MgmError::LibYubiHsm(e))
        }
    }
}

pub fn java_import_key(session:&Session, key:&mut ObjectDescriptor, key_der:&[u8], cert_der:&[u8]) -> Result<u16, MgmError> {

    if key.id != 0 {
        import_asym_object(session, key, key_der)?;
    } else {
        loop {
            let mut import_key = key.clone();
            import_asym_object(session, &mut import_key, key_der)?;
            if session.get_object_info(import_key.id, ObjectType::Opaque).is_err() {
                key.id = import_key.id;
                break;
            }
            session.delete_object(import_key.id, ObjectType::AsymmetricKey)?;
        }
    }

    let cert_capabilities =
        if key.capabilities.contains(&ObjectCapability::ExportableUnderWrap) {
            vec![ObjectCapability::ExportableUnderWrap]
        } else {
            vec![]
        };
    let res = session.import_cert(
        key.id,
        key.label.as_str(),
        key.domains.as_slice(),
        cert_capabilities.as_slice(),
        cert_der);

    match res {
        Ok(_) => Ok(key.id),
        Err(e) => {
            session.delete_object(key.id, ObjectType::AsymmetricKey)?;
            Err(MgmError::LibYubiHsm(e))
        }
    }
}



















pub fn get_asym_object_from_der(der_bytes:&[u8]) -> Result<(ObjectType, ObjectAlgorithm, Vec<u8>), MgmError> {
    if der_bytes.is_empty() {
        return Err(MgmError::InvalidInput("DER data is empty".to_string()));
    }
    if let Ok(privkey) = openssl::pkey::PKey::private_key_from_der(der_bytes) {
        return match privkey.id() {
            pkey::Id::RSA => {
                let private_rsa = privkey.rsa()?;
                let key_algorithm = get_rsa_key_algo(private_rsa.size())?;

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

                let key_algorithm = get_algo_from_nid(nid)?;
                Ok((ObjectType::AsymmetricKey, key_algorithm, s.to_vec()))
            }
            pkey::Id::ED25519 => {
                let private_ed = PKey::private_key_from_raw_bytes(der_bytes, pkey::Id::ED25519)?;
                let k = private_ed.raw_private_key()?;
                Ok((ObjectType::AsymmetricKey, ObjectAlgorithm::Ed25519, k.to_vec()))
            }
            _ => Err(MgmError::InvalidInput("Unknown or unsupported key type".to_string())),
        }
    }

    if let Ok(pubkey) = openssl::pkey::PKey::public_key_from_der(der_bytes) {
        return match pubkey.id() {
            pkey::Id::RSA => {
                let public_rsa = pubkey.rsa()?;
                let n = public_rsa.n();
                let e = public_rsa.e();

                let mut key_bytes = n.to_vec();
                key_bytes.extend_from_slice(&e.to_vec());
                let key_algorithm = get_rsa_key_algo(public_rsa.size())?;
                Ok((ObjectType::PublicKey, key_algorithm, key_bytes))
            }
            pkey::Id::EC => {
                let public_ec = pubkey.ec_key()?;
                let group = public_ec.group();
                let point = public_ec.public_key();
                let mut ctx = BigNumContext::new()?;
                let pubkey_bytes = point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

                let Some(nid) = group.curve_name() else {
                    return Err(MgmError::InvalidInput("Failed to read EC curve name".to_string()))
                };

                let key_algorithm = get_algo_from_nid(nid)?;
                Ok((ObjectType::PublicKey, key_algorithm, pubkey_bytes.to_vec()))
            }
            pkey::Id::ED25519 => {
                let public_ed = PKey::public_key_from_raw_bytes(der_bytes, pkey::Id::ED25519)?;
                let k = public_ed.raw_public_key()?;
                Ok((ObjectType::PublicKey, ObjectAlgorithm::Ed25519, k.to_vec()))
            }
            _ => Err(MgmError::InvalidInput("Unknown or unsupported key type".to_string())),
        }
    }

    if openssl::x509::X509::from_der(der_bytes).is_ok() {
        return Ok((ObjectType::Opaque, ObjectAlgorithm::OpaqueX509Certificate, der_bytes.to_vec()))
    }

    Err(MgmError::InvalidInput("Failed to parse PEM data as either private key, public key or X509Certificate".to_string()))
}

pub fn get_der_pubkey_as_pem(der_bytes:&[u8], algorithm:ObjectAlgorithm) -> Result<Vec<u8>, MgmError> {
    let pem_bytes = if RSA_KEY_ALGORITHM.contains(&algorithm) {
        let e = BigNum::from_slice(&[0x01, 0x00, 0x01])?;
        let n = BigNum::from_slice(der_bytes)?;
        let rsa_pubkey = openssl::rsa::Rsa::from_public_components(n, e)?;
        rsa_pubkey.public_key_to_pem()?
    } else if EC_KEY_ALGORITHM.contains(&algorithm) {
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
        ec_pubkey_bytes.push(0x04);
        ec_pubkey_bytes.extend(der_bytes);
        let ec_point = EcPoint::from_bytes(&ec_group, ec_pubkey_bytes.as_slice(), &mut ctx)?;
        let ec_pubkey = EcKey::from_public_key(&ec_group, &ec_point)?;
        ec_pubkey.public_key_to_pem()?
    } else if algorithm == ObjectAlgorithm::Ed25519 {
        let ed_pubkey = PKey::public_key_from_raw_bytes(der_bytes, pkey::Id::ED25519)?;
        ed_pubkey.public_key_to_pem()?
    } else {
        return Err(MgmError::InvalidInput(
            format!("Unknown or unsupported asymmetric key algorithm {:?}", algorithm)));
    };
    Ok(pem_bytes)
}

fn import_attestation_template(session:&Session, attesting_key:u16, template_cert_der:&[u8]) -> Result<bool, MgmError> {
    if !template_cert_der.is_empty() && openssl::x509::X509::from_der(template_cert_der).is_err() {
        return Err(MgmError::InvalidInput("Provided template certificate is not a valid X509Certificate".to_string()));
    }

    match session.get_object_info(attesting_key, ObjectType::Opaque) {
        Ok(opaque) => {
            if !template_cert_der.is_empty() || opaque.algorithm != ObjectAlgorithm::OpaqueX509Certificate {
                return Err(MgmError::Error("An opaque object with the same ID as the attesting key already exists on the device".to_string()))
            }
            Ok(false)
        },
        Err(_) => {
            if !template_cert_der.is_empty() {
                session.import_cert(attesting_key, "template_cert", &ObjectDomain::from_primitive(0xFFFF),&Vec::new(), template_cert_der)?;
            } else {
                let template_cert = session.sign_attestation_certificate(attesting_key, 0)?;
                session.import_cert(attesting_key, "template_cert", &ObjectDomain::from_primitive(0xFFFF), &Vec::new(), template_cert.as_slice())?;
            }
            Ok(true)
        }
    }
}





















fn get_rsa_key_algo(size_in_bytes:u32) -> Result<ObjectAlgorithm, MgmError> {
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

fn get_hashed_bytes(algo: &ObjectAlgorithm, input: &[u8]) -> Result<Vec<u8>, MgmError> {
    match algo {
        ObjectAlgorithm::RsaPkcs1Sha1 |
        ObjectAlgorithm::RsaPssSha1 |
        ObjectAlgorithm::EcdsaSha1 |
        ObjectAlgorithm::RsaOaepSha1 => Ok(openssl::hash::hash(MessageDigest::sha1(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha256 |
        ObjectAlgorithm::RsaPssSha256 |
        ObjectAlgorithm::EcdsaSha256 |
        ObjectAlgorithm::RsaOaepSha256 => Ok(openssl::hash::hash(MessageDigest::sha256(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha384 |
        ObjectAlgorithm::RsaPssSha384 |
        ObjectAlgorithm::EcdsaSha384 |
        ObjectAlgorithm::RsaOaepSha384 => Ok(openssl::hash::hash(MessageDigest::sha384(), input)?.to_vec()),
        ObjectAlgorithm::RsaPkcs1Sha512 |
        ObjectAlgorithm::RsaPssSha512 |
        ObjectAlgorithm::EcdsaSha512 |
        ObjectAlgorithm::RsaOaepSha512 => Ok(openssl::hash::hash(MessageDigest::sha512(), input)?.to_vec()),
        _ => Err(MgmError::InvalidInput("Algorithm does not contain hash component".to_string()))
    }
}

fn get_mgf1_algorithm(algo: &ObjectAlgorithm) -> Result<ObjectAlgorithm, MgmError> {
    match algo {
        ObjectAlgorithm::RsaOaepSha1 | ObjectAlgorithm::RsaPssSha1 => Ok(ObjectAlgorithm::Mgf1Sha1),
        ObjectAlgorithm::RsaOaepSha256 | ObjectAlgorithm::RsaPssSha256 => Ok(ObjectAlgorithm::Mgf1Sha256),
        ObjectAlgorithm::RsaOaepSha384 | ObjectAlgorithm::RsaPssSha384 => Ok(ObjectAlgorithm::Mgf1Sha384),
        ObjectAlgorithm::RsaOaepSha512 | ObjectAlgorithm::RsaPssSha512 => Ok(ObjectAlgorithm::Mgf1Sha512),
        _ => Err(MgmError::InvalidInput("Algorithm is not an RSA PSS or OAEP decryption algorithm".to_string())),
    }
}