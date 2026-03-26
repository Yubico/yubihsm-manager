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

use super::utils::*;
use yubihsmrs::object::*;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::hsm_operations::wrap::WrapOperations;
use crate::common::types::NewObjectSpec;
use crate::traits::operation_traits::YubihsmOperations;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ecdsa::EcdsaSig;
use openssl::sign::Verifier;
use openssl::rsa::{Rsa, Padding};
use openssl::encrypt::Encrypter;
use openssl::hash::MessageDigest;
use pem::Pem;


const OBJECT_ID:u16 = 100;

// ════════════════════════════════════════════════════════════════
//  B.1 — Generate
// ════════════════════════════════════════════════════════════════

/// Build a NewObjectSpec for an asymmetric key.
pub fn make_asym_spec(
    id: u16,
    label: &str,
    algorithm: ObjectAlgorithm,
    capabilities: Vec<ObjectCapability>,
    key_data: Option<Vec<u8>>,
) -> NewObjectSpec {
    NewObjectSpec {
        id,
        object_type: ObjectType::AsymmetricKey,
        label: label.to_string(),
        algorithm,
        domains: vec![ObjectDomain::One],
        capabilities,
        delegated_capabilities: vec![],
        data: if key_data.is_none() { vec ! [] } else { vec ! [key_data.unwrap()] },
    }
}

/// Build a NewObjectSpec for importing an X509 certificate (Opaque object).
pub fn make_cert_import_spec(
    id: u16,
    label: &str,
    der_bytes: Vec<u8>,
) -> NewObjectSpec {
    NewObjectSpec {
        id,
        object_type: ObjectType::Opaque,
        label: label.to_string(),
        algorithm: ObjectAlgorithm::OpaqueX509Certificate,
        domains: vec![ObjectDomain::One],
        capabilities: vec![ObjectCapability::ExportableUnderWrap],
        delegated_capabilities: vec![],
        data: vec![der_bytes],
    }
}

#[test]
fn test_generate_ecp256() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-ecp256", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::DeriveEcdh,
             ObjectCapability::ExportableUnderWrap, ObjectCapability::SignAttestationCertificate], None
    );

    let returned_id = AsymmetricOperations.generate(&session, &spec).expect("Failed to generate EcP256 key");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for generated EcP256 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::EcP256);
    assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());
    assert!(desc.capabilities.contains(&ObjectCapability::DeriveEcdh));
    assert!(desc.capabilities.contains(&ObjectCapability::SignAttestationCertificate));

    session.delete_object(desc.id, desc.object_type).expect("Failed to delete generated EcP256 key");

    assert!(session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).is_err(), "Object should be deleted");
}

#[test]
fn test_generate_ed25519() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-ed25519", ObjectAlgorithm::Ed25519,
        vec![ObjectCapability::SignEddsa, ObjectCapability::ExportableUnderWrap], None
    );

    let returned_id = AsymmetricOperations.generate(&session, &spec).expect("Failed to generate Ed25519 key");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for generated Ed25519 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Ed25519);
    assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());
    assert!(desc.capabilities.contains(&ObjectCapability::SignEddsa));
    assert!(desc.capabilities.contains(&ObjectCapability::ExportableUnderWrap));

    session.delete_object(desc.id, desc.object_type).expect("Failed to delete generated Ed25519 key");
        assert!(session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).is_err(), "Object should be deleted");
}

#[test]
fn test_generate_rsa2048() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-rsa2048", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPkcs, ObjectCapability::SignPss,
             ObjectCapability::DecryptPkcs, ObjectCapability::DecryptOaep,
             ObjectCapability::ExportableUnderWrap, ObjectCapability::SignAttestationCertificate], None
    );

    let returned_id = AsymmetricOperations.generate(&session, &spec).expect("Failed to generate RSA 2048 key");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for generated RSA 2048 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Rsa2048);
    assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());
    assert!(desc.capabilities.contains(&ObjectCapability::DecryptPkcs));
    assert!(desc.capabilities.contains(&ObjectCapability::DecryptOaep));

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated RSA 2048 key");
    assert!(session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).is_err(), "Object should be deleted");
}

#[test]
fn test_generate_duplicate_id_fails() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-dup", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa], None
    );

    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate first key with ID 100");
    // Second generate with same ID should fail
    let result = AsymmetricOperations.generate(&session, &spec);
    assert!(result.is_err(), "Duplicate ID should fail");

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated key with duplicate ID");
}

// ════════════════════════════════════════════════════════════════
//  B.2 — Import (using openssl to generate key material locally)
// ════════════════════════════════════════════════════════════════

/// Generate an EcP256 key pair locally, return (private_scalar, public_pem).
fn generate_local_ecp256_keypair() -> (Vec<u8>, Pem) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");
    let key = EcKey::generate(&group).expect("Failed to generate EC key");
    let privkey_bytes = key.private_key().to_vec();

    // Get public key in PEM format for use as ECDH peer
    let pkey = PKey::from_ec_key(key).expect("Failed to create PKey from EC key");
    let pub_pem_bytes = pkey.public_key_to_pem().unwrap();
    let pub_pem = pem::parse(pub_pem_bytes).unwrap();

    (privkey_bytes, pub_pem)
}

/// Generate a local RSA 2048 key and return (p || q) bytes for import.
fn generate_local_rsa2048_pq() -> Vec<u8> {
    use openssl::rsa::Rsa;
    let rsa = Rsa::generate(2048).expect("Failed to generate RSA 2048 key");
    let p = rsa.p().expect("Failed to extract p from OpenSSL generated RSA key").to_vec();
    let q = rsa.q().expect("Failed to extract q from OpenSSL generated RSA key").to_vec();
    let mut pq = p;
    pq.extend(q);
    pq
}

/// Generate a self-signed X509 cert (DER) from a local EcP256 key.
fn generate_local_self_signed_cert_der() -> Vec<u8> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};
    use openssl::hash::MessageDigest;
    use openssl::bn::BigNum;
    use openssl::asn1::Asn1Integer;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");
    let ec_key = EcKey::generate(&group).expect("Failed to generate EC key");
    let pkey = PKey::from_ec_key(ec_key).expect("Failed to create PKey from EC key");

    let mut name = X509NameBuilder::new().expect("Failed to create X509NameBuilder");
    name.append_entry_by_text("CN", "test-cert").expect("Failed to set CN in cert subject");
    let name = name.build();

    let mut builder = X509::builder().expect("Failed to create X509 builder");
    builder.set_version(2).expect("Failed to set X509 version");
    let serial = BigNum::from_u32(1).expect("Failed to create serial number");
    let serial = Asn1Integer::from_bn(&serial).expect("Failed to convert serial number to ASN1 integer");
    builder.set_serial_number(&serial).expect("Failed to set serial number");
    builder.set_subject_name(&name).expect("Failed to set subject name");
    builder.set_issuer_name(&name).expect("Failed to set issuer name");
    builder.set_pubkey(&pkey).expect("Failed to set public key in cert");
    builder.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap()).expect("Failed to set notBefore in cert");
    builder.set_not_after(&openssl::asn1::Asn1Time::days_from_now(365).unwrap()).expect("Failed to set notAfter in cert");
    builder.sign(&pkey, MessageDigest::sha256()).expect("Failed to sign cert");

    builder.build().to_der().expect("Failed to convert cert to DER")
}

#[test]
fn test_import_ecp256_privkey() {
    let (_h, session) = open_session();
    let (privkey, _) = generate_local_ecp256_keypair();
    let spec = make_asym_spec(
        OBJECT_ID, "test-import-ec", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap],
        Some(privkey),
    );

    let returned_id = AsymmetricOperations.import(&session, &spec).expect("Failed to import EcP256 private key");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for imported EcP256 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::EcP256);
    assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());
    assert!(desc.capabilities.contains(&ObjectCapability::SignEcdsa));
    assert!(desc.capabilities.contains(&ObjectCapability::ExportableUnderWrap));

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported EcP256 key");
    assert!(session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).is_err(), "Object should be deleted");
}

#[test]
fn test_import_rsa2048_privkey() {
    let (_h, session) = open_session();
    let pq = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        OBJECT_ID, "test-import-rsa", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPkcs, ObjectCapability::DecryptPkcs,
             ObjectCapability::ExportableUnderWrap],
        Some(pq),
    );

    let returned_id = AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA 2048 private key");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for imported RSA 2048 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Rsa2048);
    assert_eq!(desc.object_type, ObjectType::AsymmetricKey);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());
    assert!(desc.capabilities.contains(&ObjectCapability::SignPkcs));
    assert!(desc.capabilities.contains(&ObjectCapability::DecryptPkcs));

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported RSA 2048 key");
}

#[test]
fn test_import_x509_cert() {
    let (_h, session) = open_session();
    let cert_der = generate_local_self_signed_cert_der();
    let spec = make_cert_import_spec(OBJECT_ID, "test-import-cert", cert_der);

    let returned_id = AsymmetricOperations.import(&session, &spec).expect("Failed to import X509 certificate");
    assert_eq!(returned_id, OBJECT_ID);

    let desc = session.get_object_info(OBJECT_ID, ObjectType::Opaque).expect("Failed to get object info for imported X509 cert");
    assert_eq!(desc.algorithm, ObjectAlgorithm::OpaqueX509Certificate);
    assert_eq!(desc.object_type, ObjectType::Opaque);
    assert_eq!(desc.label, spec.label);
    assert_eq!(desc.capabilities.len(), spec.capabilities.len());

    session.delete_object(OBJECT_ID, ObjectType::Opaque).expect("Failed to delete imported X509 certificate");
    assert!(session.get_object_info(OBJECT_ID, ObjectType::Opaque).is_err(), "Object should be deleted");
}

// ════════════════════════════════════════════════════════════════
//  B.3 — Get Public Key
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_pubkey_ec() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-pubkey-ec", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate EcP256 key for get_pubkey test");

    let pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to retrieve public key from device");
    let pem_str = pem.to_string();
    assert!(pem_str.contains("BEGIN PUBLIC KEY"), "Got: {}", pem_str);
    assert!(pem_str.contains("END PUBLIC KEY"));

    let (obj_type, obj_algo, _) = AsymmetricOperations::parse_asym_pem(pem).expect("Failed to parse PEM");
    assert_eq!(obj_algo, ObjectAlgorithm::EcP256);
    assert_eq!(obj_type, ObjectType::PublicKey);

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated EcP256 key");
}

#[test]
fn test_get_pubkey_rsa() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-pubkey-rsa", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPkcs, ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate RSA 2048 key for get_pubkey test");

    let pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to retrieve RSA public key from device");
    let pem_str = pem.to_string();
    assert!(pem_str.contains("BEGIN PUBLIC KEY"), "Got: {}", pem_str);

    let (obj_type, obj_algo, _) = AsymmetricOperations::parse_asym_pem(pem).expect("Failed to parse PEM");
    assert_eq!(obj_algo, ObjectAlgorithm::Rsa2048);
    assert_eq!(obj_type, ObjectType::PublicKey);

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated RSA 2048 key");
}

// ════════════════════════════════════════════════════════════════
//  B.4 — Sign
// ════════════════════════════════════════════════════════════════

/// Verify an ECDSA signature using the public key PEM from the YubiHSM.
fn verify_ecdsa_signature(pubkey_pem: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    let pkey = PKey::public_key_from_pem(pubkey_pem).expect("Failed to parse EC public key PEM");
    let ec_key = pkey.ec_key().expect("Failed to get EC key from PKey");
    let ecdsa_sig = EcdsaSig::from_der(signature).expect("Failed to parse ECDSA signature DER");
    ecdsa_sig.verify(digest, &ec_key).expect("Failed to verify ECDSA signature")
}

/// Verify an Ed25519 signature using the public key PEM from the YubiHSM.
fn verify_eddsa_signature(pubkey_pem: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let pkey = PKey::public_key_from_pem(pubkey_pem).expect("Failed to parse ED public key PEM");
    let mut verifier = Verifier::new_without_digest(&pkey).expect("Failed to create verifier for Ed25519");
    verifier.verify_oneshot(signature, data).expect("Failed to verify Ed25519 signature")
}

/// Verify an RSA PKCS#1 v1.5 signature using the public key PEM from the YubiHSM.
fn verify_rsa_pkcs1_signature(
    pubkey_pem: &[u8],
    data: &[u8],
    signature: &[u8],
    digest: openssl::hash::MessageDigest,
) -> bool {
    let pkey = PKey::public_key_from_pem(pubkey_pem).expect("Failed to parse RSA public key PEM");
    let mut verifier = Verifier::new(digest, &pkey).expect("Failed to create verifier for RSA PKCS#1");
    verifier.update(data).expect("Failed to update verifier with data");
    verifier.verify(signature).expect("Failed to verify RSA PKCS#1 signature")
}

/// Verify an RSA PSS signature using the public key PEM from the YubiHSM.
fn verify_rsa_pss_signature(
    pubkey_pem: &[u8],
    data: &[u8],
    signature: &[u8],
    digest: openssl::hash::MessageDigest,
) -> bool {
    let pkey = PKey::public_key_from_pem(pubkey_pem).expect("Failed to parse RSA public key PEM");
    let mut verifier = Verifier::new(digest, &pkey).expect("Failed to create verifier for RSA PSS");
    verifier.set_rsa_padding(Padding::PKCS1_PSS).expect("Failed to set RSA PSS padding");
    verifier.set_rsa_mgf1_md(digest).expect("Failed to set RSA PSS MGF1 digest");
    verifier.update(data).expect("Failed to update verifier with data");
    verifier.verify(signature).expect("Failed to verify RSA PSS signature")
}

#[test]
fn test_sign_ecdsa_sha256() {
    let (_h, session) = open_session();
    let (privkey, _) = generate_local_ecp256_keypair();
    let spec = make_asym_spec(
        OBJECT_ID, "test-sign-ecdsa", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import EcP256 private key");

    let data = b"test data to sign with ecdsa";
    let sig = AsymmetricOperations::sign(&session, OBJECT_ID, &ObjectAlgorithm::EcdsaSha256, data).unwrap();
    assert!(!sig.is_empty(), "Signature should not be empty");

    // Verify: the YubiHSM hashes internally, so we need the digest for ECDSA low-level verify
    let digest = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), data).expect("Failed to compute digest of data");
    let pubkey_pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey)
        .expect("Failed to get public key from device").to_string().into_bytes();
    assert!(
        verify_ecdsa_signature(&pubkey_pem, &digest, &sig),
        "ECDSA-SHA256 signature should verify against the YubiHSM public key"
    );

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported EcP256 key");
}

#[test]
fn test_sign_eddsa() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-sign-eddsa", ObjectAlgorithm::Ed25519,
        vec![ObjectCapability::SignEddsa, ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate Ed25519 key for signing test");

    let data = b"test data to sign with ed25519";
    let sig = AsymmetricOperations::sign(&session, OBJECT_ID, &ObjectAlgorithm::Ed25519, data).expect("Failed to sign with Ed25519 key");
    assert!(!sig.is_empty(), "Ed25519 signature should not be empty");
    assert_eq!(sig.len(), 64, "Ed25519 signature should be 64 bytes");

    // Verify: Ed25519 does not pre-hash; raw data is passed to verify
    let pubkey_pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey)
        .expect("Failed to get public key from device").to_string().into_bytes();
    assert!(
        verify_eddsa_signature(&pubkey_pem, data, &sig),
        "Ed25519 signature should verify against the YubiHSM public key"
    );

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated Ed25519 key");
}

#[test]
fn test_sign_rsa_pkcs1_sha256() {
    let (_h, session) = open_session();
    let privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        OBJECT_ID, "test-sign-rsa-pkcs", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPkcs, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA 2048 key for signing test");

    let data = b"test data for rsa pkcs1";
    let sig = AsymmetricOperations::sign(&session, OBJECT_ID, &ObjectAlgorithm::RsaPkcs1Sha256, data).unwrap();
    assert_eq!(sig.len(), 256, "RSA 2048 signature should be 256 bytes");

    // Verify using high-level OpenSSL Verifier (handles hashing + padding)
    let pubkey_pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey)
        .expect("Failed to get public key from device").to_string().into_bytes();
    assert!(
        verify_rsa_pkcs1_signature(&pubkey_pem, data, &sig, openssl::hash::MessageDigest::sha256()),
        "RSA PKCS#1 v1.5 SHA-256 signature should verify"
    );

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated RSA 2048 key");
}

#[test]
fn test_sign_rsa_pss_sha256() {
    let (_h, session) = open_session();
    let privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        OBJECT_ID, "test-sign-rsa-pss", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPss, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA 2048 key for signing test");

    let data = b"test data for rsa pss";
    let sig = AsymmetricOperations::sign(&session, OBJECT_ID, &ObjectAlgorithm::RsaPssSha256, data).unwrap();
    assert_eq!(sig.len(), 256, "RSA 2048 PSS signature should be 256 bytes");

    // Verify using high-level OpenSSL Verifier with PSS padding
    let pubkey_pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey)
        .expect("Failed to get public key from device").to_string().into_bytes();
    assert!(
        verify_rsa_pss_signature(&pubkey_pem, data, &sig, openssl::hash::MessageDigest::sha256()),
        "RSA PSS SHA-256 signature should verify"
    );

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated RSA 2048 key");
}

#[test]
fn test_sign_empty_data() {
    let (_h, session) = open_session();
    let (privkey, _) = generate_local_ecp256_keypair();
    let spec = make_asym_spec(
        OBJECT_ID, "test-sign-empty", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import EcP256 private key");

    let data: &[u8] = b"";
    let sig = AsymmetricOperations::sign(&session, OBJECT_ID, &ObjectAlgorithm::EcdsaSha256, data).unwrap();
    assert!(!sig.is_empty(), "Signing empty data should still produce an empty signature");

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported EcP256 key");
}

// ════════════════════════════════════════════════════════════════
//  B.5 — Decrypt
// ════════════════════════════════════════════════════════════════

/// Encrypt `plaintext` with the given RSA public key PEM using PKCS1v1.5.
fn rsa_encrypt_pkcs1(pubkey_pem: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(pubkey_pem).expect("Failed to parse RSA public key PEM");
    let mut buf = vec![0u8; rsa.size() as usize];
    let len = rsa.public_encrypt(plaintext, &mut buf, Padding::PKCS1).expect("Failed to encrypt with RSA PKCS#1");
    buf.truncate(len);
    buf
}

/// Encrypt `plaintext` with the given RSA public key PEM using OAEP-SHA256.
fn rsa_encrypt_oaep_sha256(pubkey_pem: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let rsa = Rsa::public_key_from_pem(pubkey_pem).expect("Failed to parse RSA public key PEM");
    let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA public key");
    let mut encrypter = Encrypter::new(&pkey).expect("Failed to create encrypter for RSA OAEP");
    encrypter.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP).expect("Failed to set RSA OAEP padding");
    encrypter.set_rsa_oaep_md(MessageDigest::sha256()).expect("Failed to set RSA OAEP digest");
    encrypter.set_rsa_mgf1_md(MessageDigest::sha256()).expect("Failed to set RSA OAEP MGF1 digest");

    let buf_len = encrypter.encrypt_len(plaintext).expect("Failed to get buffer length for RSA OAEP encryption");
    let mut buf = vec![0u8; buf_len];
    let len = encrypter.encrypt(plaintext, &mut buf).expect("Failed to encrypt with RSA OAEP");
    buf.truncate(len);
    buf
}

#[test]
fn test_decrypt_rsa_pkcs1() {
    let (_h, session) = open_session();
    let privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        OBJECT_ID, "test-dec-pkcs1", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::DecryptPkcs, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA 2048 key for decryption test");

    // Get public key from YubiHSM and encrypt locally
    let pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get RSA public key from device");
    let pem_bytes = pem.to_string().into_bytes();
    let plaintext = b"hello world";
    let ciphertext = rsa_encrypt_pkcs1(&pem_bytes, plaintext);

    // Decrypt on YubiHSM
    let decrypted = AsymmetricOperations::decrypt(
        &session, OBJECT_ID, &ObjectAlgorithm::RsaPkcs1Decrypt, &ciphertext,
    ).expect("Failed to decrypt with RSA PKCS#1 decryption");
    assert_eq!(decrypted, plaintext, "Decrypted data should match original");

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported RSA 2048 key");
}

#[test]
fn test_decrypt_rsa_oaep_sha256() {
    let (_h, session) = open_session();
    let privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        OBJECT_ID, "test-dec-oaep", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::DecryptOaep, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA 2048 key for decryption test");

    let pem = AsymmetricOperations::get_pubkey(&session, OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get RSA public key from device");
    let pem_bytes = pem.to_string().into_bytes();
    let plaintext = b"hello world";
    let ciphertext = rsa_encrypt_oaep_sha256(&pem_bytes, plaintext);

    let decrypted = AsymmetricOperations::decrypt(
        &session, OBJECT_ID, &ObjectAlgorithm::RsaOaepSha256, &ciphertext,
    ).expect("Failed to decrypt with RSA OAEP decryption");
    assert_eq!(decrypted, plaintext, "OAEP decrypted data should match original");

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported RSA 2048 key");
}

// ════════════════════════════════════════════════════════════════
//  B.6 — ECDH
// ════════════════════════════════════════════════════════════════

#[test]
fn test_derive_ecdh_ecp256() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-ecdh", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::DeriveEcdh, ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate EcP256 key for ECDH test");

    // Get YubiHSM key descriptor for derive_ecdh
    let hsm_key = session.get_object_info(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to get object info for ECDH key");

    // Generate a local EcP256 peer key and get its public DER
    let (_, peer_pem) = generate_local_ecp256_keypair();

    let shared_secret = AsymmetricOperations::derive_ecdh(&session, &hsm_key, peer_pem).expect("Failed to derive ECDH shared secret");
    assert_eq!(shared_secret.len(), 32, "EcP256 ECDH shared secret should be 32 bytes");

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated EcP256 key");
}

// ════════════════════════════════════════════════════════════════
//  B.7 — Attestation
// ════════════════════════════════════════════════════════════════

#[test]
fn test_attestation_device_signed() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-attest-dev", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::SignAttestationCertificate,
             ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate key for attestation test");

    // attesting_key = 0 means device attestation key signs it
    let res = AsymmetricOperations::get_attestation_cert(&session, OBJECT_ID, 0, None);
    match res {
        Ok(cert_pem) => {
            let pem_str = cert_pem.to_string();
            assert!(pem_str.contains("BEGIN CERTIFICATE"), "Got: {}", pem_str);
            assert!(pem_str.contains("END CERTIFICATE"));

            let (obj_type, obj_algo, _) = AsymmetricOperations::parse_asym_pem(cert_pem).expect("Failed to parse attestation cert PEM");
            assert_eq!(obj_algo, ObjectAlgorithm::OpaqueX509Certificate);
            assert_eq!(obj_type, ObjectType::Opaque);
        }
        Err(_) => eprintln!("Device did not return an attestation certificate. Possibly because device does not come with an attestation key.")
    }
    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated key");
}

#[test]
fn test_attestation_selfsigned() {
    let (_h, session) = open_session();
    let spec = make_asym_spec(
        OBJECT_ID, "test-attest-dev", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::SignAttestationCertificate,
             ObjectCapability::ExportableUnderWrap], None
    );
    AsymmetricOperations.generate(&session, &spec).expect("Failed to generate key for attestation test");

    let cert_pem = AsymmetricOperations::get_attestation_cert(&session, OBJECT_ID, OBJECT_ID, None).expect("Failed to get self-signed attestation cert");
    let pem_str = cert_pem.to_string();
    assert!(pem_str.contains("BEGIN CERTIFICATE"), "Got: {}", pem_str);
    assert!(pem_str.contains("END CERTIFICATE"));

    let (obj_type, obj_algo, _) = AsymmetricOperations::parse_asym_pem(cert_pem).expect("Failed to parse attestation cert PEM");
    assert_eq!(obj_algo, ObjectAlgorithm::OpaqueX509Certificate);
    assert_eq!(obj_type, ObjectType::Opaque);

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete generated key");
    assert!(session.get_object_info(OBJECT_ID, ObjectType::Opaque).is_err(), "Template certificate should have been deleted");
}

// ════════════════════════════════════════════════════════════════
//  B.8 — Listing
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_all_asym_objects() {
    let (_h, session) = open_session();
    let (priv_ec, _) = generate_local_ecp256_keypair();
    let spec_ec = make_asym_spec(
        OBJECT_ID, "test-list-asym", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], Some(priv_ec)
    );
    AsymmetricOperations.import(&session, &spec_ec).expect("Failed to import EC key for listing test");

    let ed_spec = make_asym_spec(
        0, "test-list-asym_2", ObjectAlgorithm::Ed25519,
        vec![ObjectCapability::SignEddsa, ObjectCapability::ExportableUnderWrap], None
    );
    let ed_id = AsymmetricOperations.generate(&session, &ed_spec).expect("Failed to generate ED key for listing test");

     let wrap_spec = NewObjectSpec {
        id: 0,
        label: "test-list-asym_3".to_string(),
        object_type: ObjectType::WrapKey,
        algorithm: ObjectAlgorithm::Aes192CcmWrap,
        domains: vec![ObjectDomain::One],
        capabilities: vec![ObjectCapability::ImportWrapped, ObjectCapability::ExportWrapped],
        delegated_capabilities: vec![],
        data: vec![],
    };
    let wrap_id = WrapOperations.generate(&session, &wrap_spec).expect("Failed to generate wrap key for listing test");


    let objects = AsymmetricOperations.get_all_objects(&session).expect("Failed to get all objects from device");
    assert_eq!(objects.len(), 2, "Should have 3 objects (EC key and ED key. Symmetric key should not be listed)");
    assert!(objects.iter().any(|o| o.id == OBJECT_ID),
            "Imported EC key should appear in get_all_objects"
    );
    assert!(objects.iter().any(|o| o.id == ed_id),
            "Generated ED key should appear in get_all_objects"
    );
    assert!(!objects.iter().any(|o| o.id == wrap_id),
            "Generated wrap key should not appear in get_all_objects"
    );

    session.delete_object(OBJECT_ID, ObjectType::AsymmetricKey).expect("Failed to delete imported EC key");
    session.delete_object(ed_id, ObjectType::AsymmetricKey).expect("Failed to delete generated ED key");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete generated wrap key");
}

#[test]
fn test_get_signing_keys() {
    let (_h, session) = open_session();
    let (privkey, _) = generate_local_ecp256_keypair();
    let spec_1 = make_asym_spec(
        0, "test-signkeys", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], Some(privkey.clone())
    );
    let id_1 = AsymmetricOperations.import(&session, &spec_1).expect("Failed to import signing key for get_signing_keys test");

    let spec_2 = make_asym_spec(
        0, "test-non_signkeys", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::DeriveEcdh, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    let id_2 = AsymmetricOperations.import(&session, &spec_2).expect("Failed to import non-signing key for get_signing_keys test");

    let authkey = session
        .get_object_info(DEFAULT_AUTHKEY_ID, ObjectType::AuthenticationKey)
        .expect("Failed to get authkey object info");

    let signing_keys = AsymmetricOperations::get_signing_keys(&session, &authkey).expect("Failed to get signing keys from device");
    assert!(
        signing_keys.iter().any(|k| k.id == id_1),
        "Key with signing capability should appear in get_signing_keys"
    );
    assert!(
        !signing_keys.iter().any(|k| k.id == id_2),
        "Key without signing capability should not appear in get_signing_keys"
    );

    session.delete_object(id_1, ObjectType::AsymmetricKey).expect("Failed to delete first signing key");
    session.delete_object(id_2, ObjectType::AsymmetricKey).expect("Failed to delete second signing key");
}

#[test]
fn test_get_decryption_keys() {
    let (_h, session) = open_session();
    let privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        0, "test-deckeys", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::DecryptPkcs, ObjectCapability::ExportableUnderWrap], Some(privkey.clone())
    );
    let id_1 = AsymmetricOperations.import(&session, &spec).expect("Failed to import decryption key for get_decryption_keys test");

    let spec = make_asym_spec(
        0, "test-deckeys", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::SignPkcs, ObjectCapability::ExportableUnderWrap], Some(privkey.clone())
    );
    let id_2 = AsymmetricOperations.import(&session, &spec).expect("Failed to import non-decryption key for get_decryption_keys test");

    let spec = make_asym_spec(
        0, "test-deckeys", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::DecryptPkcs, ObjectCapability::ExportableUnderWrap], None
    );
    let id_3 = AsymmetricOperations.generate(&session, &spec).expect("Failed to generate EC key with decryption capabilities for get_decryption_keys test");

    let authkey = session
        .get_object_info(DEFAULT_AUTHKEY_ID, ObjectType::AuthenticationKey)
        .expect("Failed to get authkey object info");

    let dec_keys = AsymmetricOperations::get_decryption_keys(&session, &authkey).expect("Failed to get decryption keys from device");
    assert!(
        dec_keys.iter().any(|k| k.id == id_1),
        "RSA key with decryption capability should appear in get_decryption_keys"
    );
    assert!(
        !dec_keys.iter().any(|k| k.id == id_2),
        "RSA key without decryption capabilities should not appear in get_decryption_keys"
    );
    assert!(
        !dec_keys.iter().any(|k| k.id == id_3),
        "EC key with the right decryption capabilities should not appear in get_decryption_keys"
    );

    session.delete_object(id_1, ObjectType::AsymmetricKey).expect("Failed to delete first decryption key");
    session.delete_object(id_2, ObjectType::AsymmetricKey).expect("Failed to delete second decryption key");
    session.delete_object(id_3, ObjectType::AsymmetricKey).expect("Failed to delete third decryption key");
}

#[test]
fn test_get_derivation_keys() {
    let (_h, session) = open_session();
    let (privkey, _) = generate_local_ecp256_keypair();
    let spec = make_asym_spec(
        0, "test-derivekeys", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::DeriveEcdh, ObjectCapability::ExportableUnderWrap], Some(privkey.clone())
    );
    let id_1 = AsymmetricOperations.import(&session, &spec).expect("Failed to import EC key with ECDH derivation capability for get_derivation_keys test");

    let spec = make_asym_spec(
        0, "test-derivekeys", ObjectAlgorithm::EcP256,
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap], Some(privkey)
    );
    let id_2 = AsymmetricOperations.import(&session, &spec).expect("Failed to import EC key without ECDH derivation capability for get_derivation_keys test");

    let rsa_privkey = generate_local_rsa2048_pq();
    let spec = make_asym_spec(
        0, "test-derivekeys", ObjectAlgorithm::Rsa2048,
        vec![ObjectCapability::DeriveEcdh, ObjectCapability::ExportableUnderWrap], Some(rsa_privkey)
    );
    let id_3 = AsymmetricOperations.import(&session, &spec).expect("Failed to import RSA key with ECDH derivation capability for get_derivation_keys test");

    let authkey = session
        .get_object_info(DEFAULT_AUTHKEY_ID, ObjectType::AuthenticationKey)
        .expect("Failed to get authkey object info");
    let derive_keys = AsymmetricOperations::get_derivation_keys(&session, &authkey).expect("Failed to get derivation keys from device");
    assert!(
        derive_keys.iter().any(|k| k.id == id_1),
        "EC key with derivation capabilities should appear in get_derivation_keys"
    );
    assert!(
        !derive_keys.iter().any(|k| k.id == id_2),
        "EC key without derivation capabilities should not appear in get_derivation_keys"
    );
    assert!(
        !derive_keys.iter().any(|k| k.id == id_3),
        "RSA key with derivation capabilities should not appear in get_derivation_keys"
    );

    session.delete_object(id_1, ObjectType::AsymmetricKey).expect("Failed to delete first derivation key");
    session.delete_object(id_2, ObjectType::AsymmetricKey).expect("Failed to delete second derivation key");
    session.delete_object(id_3, ObjectType::AsymmetricKey).expect("Failed to delete third derivation key");
}

// ════════════════════════════════════════════════════════════════
//  B.9 — Get Certificate (Opaque X509)
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_certificate() {
    let (_h, session) = open_session();
    let cert_der = generate_local_self_signed_cert_der();
    let spec = make_cert_import_spec(0, "test-get-cert", cert_der);
    let id = AsymmetricOperations.import(&session, &spec).expect("Failed to import certificate for get_certificate test");

    let cert_pem = AsymmetricOperations::get_certificate(&session, id).expect("Failed to get certificate from device");
    let pem_str = cert_pem.to_string();
    assert!(pem_str.contains("BEGIN CERTIFICATE"), "Got: {}", pem_str);
    assert!(pem_str.contains("END CERTIFICATE"));

    let (obj_type, obj_algo, _) = AsymmetricOperations::parse_asym_pem(cert_pem).expect("Failed to parse certificate PEM");
    assert!(obj_algo == ObjectAlgorithm::OpaqueX509Certificate);
    assert!(obj_type == ObjectType::Opaque);

    session.delete_object(id, ObjectType::Opaque).expect("Failed to delete imported certificate");
}