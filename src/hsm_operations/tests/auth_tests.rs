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
use crate::hsm_operations::auth::AuthenticationOperations;
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::common::util::get_delegated_capabilities;
use crate::common::types::NewObjectSpec;
use crate::traits::operation_traits::YubihsmOperations;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use openssl::bn::BigNumContext;
use openssl::nid::Nid;

/// Build a NewObjectSpec for importing a password-derived authentication key.
pub fn make_auth_import_spec(
    id: u16,
    label: &str,
    capabilities: Vec<ObjectCapability>,
    delegated_capabilities: Vec<ObjectCapability>,
    password: String,
) -> NewObjectSpec {
    NewObjectSpec {
        id,
        object_type: ObjectType::AuthenticationKey,
        label: label.to_string(),
        algorithm: ObjectAlgorithm::Aes128YubicoAuthentication,
        domains: vec![ObjectDomain::One],
        capabilities,
        delegated_capabilities,
        data: vec![password.as_bytes().to_vec()],
    }
}

/// Build a NewObjectSpec for importing an EcP256 asymmetric authentication key.
pub fn make_auth_ecp256_import_spec(
    id: u16,
    label: &str,
    capabilities: Vec<ObjectCapability>,
    delegated_capabilities: Vec<ObjectCapability>,
    pubkey_data: Vec<u8>,
) -> NewObjectSpec {
    NewObjectSpec {
        id,
        object_type: ObjectType::AuthenticationKey,
        label: label.to_string(),
        algorithm: ObjectAlgorithm::Ecp256YubicoAuthentication,
        domains: vec![ObjectDomain::One],
        capabilities,
        delegated_capabilities,
        data: vec![pubkey_data],
    }
}

// ════════════���═══════════════════════════════════════════════════
//  D.1 — Import password-derived authentication key
// ════════════════════════════════════════════════════════════════

#[test]
fn test_import_password_auth_key() {
    let (hsm, session) = open_session();

    let password = "foo123";
    let spec = make_auth_import_spec(
        0, "test-auth-pw",
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap],
        vec![ObjectCapability::SignEcdsa],
        password.to_string(),
    );

    let id = AuthenticationOperations.import(&session, &spec).expect("Failed to import password-derived auth key");

    let desc = session.get_object_info(id, ObjectType::AuthenticationKey).unwrap();
    assert_eq!(desc.id, id);
    assert_eq!(desc.object_type, ObjectType::AuthenticationKey);
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes128YubicoAuthentication);
    assert_eq!(desc.label, "test-auth-pw");
    assert_eq!(desc.capabilities, vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap]);
    assert_eq!(get_delegated_capabilities(&desc), vec![ObjectCapability::SignEcdsa]);

    let session2 = hsm.establish_session(id, password, true).expect("Failed to establish session with imported password-derived auth key");
    assert!(session2.list_objects().is_ok(), "Asymmetric session should be able to list objects");
    session2.close().expect("Failed to close session2");


    session.delete_object(id, ObjectType::AuthenticationKey).expect("Failed to delete test auth key");
    assert!(session.get_object_info(id, ObjectType::AuthenticationKey).is_err(), "Deleted auth key should not be found");
}

#[test]
fn test_login_with_wrong_password_fails() {
    let (hsm, session) = open_session();
    let spec = make_auth_import_spec(
        0, "test-auth-wrongpw",
        vec![ObjectCapability::SignEcdsa],
        vec![],
        "foo123".to_string(),
    );
    let id = AuthenticationOperations.import(&session, &spec).expect("Initial import should succeed");

    assert!(hsm.establish_session(id, "foobar", true).is_err(), "Wrong password should fail to authenticate");

    session.delete_object(id, ObjectType::AuthenticationKey).expect("Failed to delete test auth key");
}


#[test]
fn test_import_duplicate_id_fails() {
    let (_h, session) = open_session();

    let mut spec = make_auth_import_spec(
        0, "test-auth-dup",
        vec![ObjectCapability::SignEcdsa],
        vec![],
        "foo123".to_string(),
    );

    let id = AuthenticationOperations.import(&session, &spec).expect("Initial import should succeed");
    spec.id = id;
    assert!(AuthenticationOperations.import(&session, &spec).is_err(), "Duplicate auth key ID should fail");

    session.delete_object(id, ObjectType::AuthenticationKey).expect("Failed to delete test auth key");
}

#[test]
fn test_import_unsupported_algorithm_fails() {
    let (_h, session) = open_session();

    let mut spec = make_auth_import_spec(
        0, "test-auth-bad-algo",
        vec![ObjectCapability::SignEcdsa],
        vec![],
        "foo123".to_string(),
    );
    spec.algorithm = ObjectAlgorithm::Rsa2048; // not a valid auth algorithm
    assert!(AuthenticationOperations.import(&session, &spec).is_err(), "Unsupported algorithm should fail");
}

// ════════════════════════════════��═══════════════════════════════
//  D.2 — Import EcP256 asymmetric authentication key
// ════════════════════════════════════════════════════════════════

fn generate_local_ecp256_keypair() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("Failed to create EC group");
    let ec_key = EcKey::generate(&group).expect("Failed to generate EC key");
    let mut bn_ctx = BigNumContext::new().expect("Failed to create BN context");

    // Public key in uncompressed form (0x04 || X || Y) — 65 bytes
    let pubkey_bytes = ec_key.public_key().to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut bn_ctx).unwrap();
    assert_eq!(pubkey_bytes.len(), 65, "Uncompressed EcP256 pubkey must be 65 bytes");

    // Private key scalar — 32 bytes, zero-padded on the left
    let privkey_bn = ec_key.private_key();
    let mut privkey_bytes = vec![0u8; 32];
    let bn_bytes = privkey_bn.to_vec();
    // Left-pad if the bignum is shorter than 32 bytes
    let offset = 32 - bn_bytes.len();
    privkey_bytes[offset..].copy_from_slice(&bn_bytes);

    (privkey_bytes, pubkey_bytes)
}

#[test]
fn test_import_ecp256_auth_key() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping EC P256 auth key import test: requires firmware 2.3.0 or later");
        return;
    }

    let (privkey, pubkey) = generate_local_ecp256_keypair();
    let spec = make_auth_ecp256_import_spec(
        0, "test-auth-ec",
        vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap],
        vec![ObjectCapability::SignEcdsa],
        pubkey,
    );

    let id = AuthenticationOperations.import(&session, &spec).expect("Failed to import EC P256 auth key");
    let desc = session.get_object_info(id, ObjectType::AuthenticationKey).expect("Failed to get object info for imported EC P256 auth key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Ecp256YubicoAuthentication);

    let device_pubkey = hsm.get_device_pubkey().expect("Failed to get device public key");

    let session2 = hsm.establish_session_asym(id, &privkey, &device_pubkey).expect("Failed to establish asymmetric session with imported EC P256 auth key");
    assert!(session2.list_objects().is_ok(), "Asymmetric session should be able to list objects");
    session2.close().expect("Failed to close session2");

    session.delete_object(id, ObjectType::AuthenticationKey).expect("Failed to delete test EC P256 auth key");
}


// ════════════════════════════════════════════════════════════════
//  D.3 — Listing
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_all_auth_objects_includes_default() {
    let (_h, session) = open_session();

    let objects = AuthenticationOperations.get_all_objects(&session).expect("Failed to get all auth objects");
    assert!(
        objects.iter().any(|o| o.id == DEFAULT_AUTHKEY_ID),
        "Default auth key (ID {}) should appear in listing",
        DEFAULT_AUTHKEY_ID
    );
}

#[test]
fn test_get_all_auth_objects_includes_new_key() {
    let (_h, session) = open_session();

    let spec = make_auth_import_spec(
        0, "test-auth-list",
        vec![ObjectCapability::SignEcdsa],
        vec![],
        "foo123".to_string(),
    );
    let id = AuthenticationOperations.import(&session, &spec).expect("Failed to import auth key for listing test");

    let objects = AuthenticationOperations.get_all_objects(&session).expect("Failed to get all auth objects");
    assert!(
        objects.iter().any(|o| o.id == id),
        "Newly created auth key should appear in listing"
    );

    session.delete_object(id, ObjectType::AuthenticationKey).expect("Failed to delete test auth key");
}

// ════════════════════════════════════════════════════════════════
//  D.4 — Capability enforcement: new auth key is limited
// ════════════════════════════════════════════════════════════════

#[test]
fn test_new_auth_key_capability_enforcement() {
    let (hsm, session) = open_session();
    let password = "foo123";

    // Create an auth key that can ONLY sign ECDSA — no key generation
    let spec = make_auth_import_spec(
        0, "test-auth-limited",
        vec![ObjectCapability::SignEcdsa],
        vec![],
        password.to_string(),
    );
    let auth_id = AuthenticationOperations.import(&session, &spec).expect("Failed to import limited auth key");

    // Generate an EC key with the default session for the limited user to sign with
    let spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::AsymmetricKey,
        label: "test-limited-ec".to_string(),
        algorithm: ObjectAlgorithm::EcP256,
        domains: vec![ObjectDomain::One],
        capabilities: vec![ObjectCapability::SignEcdsa, ObjectCapability::ExportableUnderWrap],
        delegated_capabilities: vec![],
        data: vec![],
    };
    let ec_id = AsymmetricOperations.generate(&session, &spec).expect("Failed to generate EC key for limited auth key test");

    let session2 = hsm.establish_session(auth_id, password, true).expect("Failed to establish session with limited auth key");

    // Signing should work
    let res = AsymmetricOperations::sign(
        &session2, ec_id, &ObjectAlgorithm::EcdsaSha256, b"test",
    );
    assert!(res.is_ok(), "Limited user should be able to sign");

    // Generating a new key should fail (no GenerateAsymmetricKey capability)
    let gen_result = AsymmetricOperations.generate(&session2, &spec);
    assert!(gen_result.is_err(), "Limited user should NOT be able to generate keys");

    session.delete_object(auth_id, ObjectType::AuthenticationKey).expect("Failed to delete limited auth key");
    session.delete_object(ec_id, ObjectType::AsymmetricKey).expect("Failed to delete EC key used in limited auth key test");
}