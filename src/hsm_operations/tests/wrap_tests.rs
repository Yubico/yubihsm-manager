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
use yubihsmrs::Session;
use crate::hsm_operations::wrap::{WrapOpSpec, WrapKeyType, WrapType, WrapOperations};
use crate::hsm_operations::asym::AsymmetricOperations;
use yubihsmrs::object::{
    ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType, ObjectOrigin
};
use crate::traits::operation_traits::YubihsmOperations;
use crate::common::types::NewObjectSpec;


// ────────────────────────────────────────────────────────────────
//  Helper: build a WrapOpSpec for AES CCM wrap
// ────────────────────────────────────────────────────────────────
fn aes_wrap_op_spec(wrapkey_id: u16) -> WrapOpSpec {
    WrapOpSpec {
        wrapkey_id,
        wrapkey_type: WrapKeyType::Aes,
        wrap_type: WrapType::Object,
        include_ed_seed: false,
        aes_algorithm: None,
        oaep_algorithm: None,
        mgf1_algorithm: None,
    }
}

// ────────────────────────────────────────────────────────────────
//  Helper: build a WrapOpSpec for RSA-OAEP export (PublicRsa)
// ────────────────────────────────────────────────────────────────
fn rsa_wrap_op_spec(wrapkey_id: u16, wrapkey_type: WrapKeyType, wrap_type: WrapType) -> WrapOpSpec {
    WrapOpSpec {
        wrapkey_id,
        wrapkey_type,
        wrap_type,
        include_ed_seed: false,
        aes_algorithm: Some(ObjectAlgorithm::Aes256),
        oaep_algorithm: Some(ObjectAlgorithm::RsaOaepSha256),
        mgf1_algorithm: Some(ObjectAlgorithm::Mgf1Sha256),
    }
}

// ────────────────────────────────────────────────────────────────
//  Helper: generate an AES-256 CCM wrap key on the YubiHSM
// ────────────────────────────────────────────────────────────────
fn generate_aes_wrap_key(session: &Session) -> u16 {
    let spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::WrapKey,
        label: "wrapkey".to_string(),
        algorithm: ObjectAlgorithm::Aes256CcmWrap,
        domains: vec![ObjectDomain::One],
        capabilities: vec![
            ObjectCapability::ExportWrapped,
            ObjectCapability::ImportWrapped,
        ],
        delegated_capabilities: vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::ExportableUnderWrap,
        ],
        data: vec![],
    };
    WrapOperations.generate(session, &spec).expect("Failed to generate AES wrap key")
}

// ────────────────────────────────────────────────────────────────
//  Helper: generate an RSA-2048 wrap key and return object_id
//  1. Generate RSA wrap key
//  2. Export its public key
//  3. Import public key as PublicWrapKey
// ────────────────────────────────────────────────────────────────
fn generate_rsa_wrap_key_pair(session: &Session) -> u16{
    let spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::WrapKey,
        label: "rsawrapkey".to_string(),
        algorithm: ObjectAlgorithm::Rsa2048,
        domains: vec![ObjectDomain::One],
        capabilities: vec![
            ObjectCapability::ImportWrapped,
        ],
        delegated_capabilities: vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::ExportableUnderWrap,
        ],
        data: vec![],
    };
    let id = WrapOperations.generate(session, &spec).expect("Failed to generate RSA wrap key pair");

    // Export the public key
    let pubkey = AsymmetricOperations::get_pubkey(session, id, &ObjectType::WrapKey)
        .expect("Failed to export RSA wrap key public key");

    let (_, _, pubkey_bytes) = AsymmetricOperations::parse_asym_pem(pubkey).expect("Failed to parse PEM public key");

    // Import as PublicWrapKey
    let spec = NewObjectSpec {
        id,
        object_type: ObjectType::PublicWrapKey,
        label: "rsawrapkey_pub".to_string(),
        algorithm: ObjectAlgorithm::Rsa2048,
        domains: vec![ObjectDomain::One],
        capabilities: vec![
        ObjectCapability::ExportWrapped,
        ],
        delegated_capabilities: vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::ExportableUnderWrap,
        ],
        data: vec![pubkey_bytes],
    };
    WrapOperations.import(session, &spec).expect("Failed to import RSA wrap public key");
    id
}

// ────────────────────────────────────────────────────────────────
//  Helper: generate a target asymmetric key for wrapping tests
// ────────────────────────────────────────────────────────────────
fn generate_target_key(session: &Session) -> u16 {
    let spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::AsymmetricKey,
        label: "targetkey".to_string(),
        algorithm: ObjectAlgorithm::EcP256,
        domains: vec![ObjectDomain::One],
        capabilities: vec![
            ObjectCapability::SignEcdsa,
            ObjectCapability::ExportableUnderWrap,
        ],
        delegated_capabilities: vec![],
        data: vec![],
    };
    AsymmetricOperations.generate(session, &spec).expect("Failed to generate target asymmetric key")
}

// ════════════════════════════════════════════════════════════════
//  E.1 — AES CCM: export and import a single object
// ════════════════════════════════════════════════════════════════
#[test]
fn test_aes_wrap_export_then_import() {
    let (_h, session) = open_session();

    // Generate wrap key and target key
    let wrap_id = generate_aes_wrap_key(&session);
    let target_id = generate_target_key(&session);
    let info = session.get_object_info(target_id, ObjectType::AsymmetricKey).expect("Failed to get object info for target key");
    assert_eq!(info.sequence(), 0);
    assert_eq!(info.origin(), &ObjectOrigin::Generated);

    // Export wrapped
    let op_spec = aes_wrap_op_spec(wrap_id);
    let export_objects = vec![ObjectHandle {
        object_id: target_id,
        object_type: ObjectType::AsymmetricKey,
    }];
    let wrapped_list = WrapOperations::export_wrapped(&session, &op_spec, &export_objects)
                                     .expect("AES export_wrapped should succeed");
    assert_eq!(wrapped_list.len(), 1, "Should have one wrapped object");
    assert_eq!(wrapped_list[0].object_id, target_id, "Wrapped object should reference original ID");
    assert_eq!(wrapped_list[0].object_type, ObjectType::AsymmetricKey, "Wrapped object should reference correct type");
    assert_eq!(wrapped_list[0].wrapkey_id, wrap_id, "Wrapped object should reference correct wrap key ID");
    assert!(wrapped_list[0].error.is_none(), "Export should succeed without error");

    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete original object");

    let imported = WrapOperations::import_wrapped(
        &session, &op_spec, &wrapped_list[0].wrapped_data, None).expect("AES import_wrapped should succeed");
    assert_eq!(imported.object_id, target_id);
    assert_eq!(imported.object_type, ObjectType::AsymmetricKey);

    // Verify restored object exists
    let info = session.get_object_info(target_id, ObjectType::AsymmetricKey).expect("Failed to get object info for restored object");
    assert_eq!(info.algorithm(), &ObjectAlgorithm::EcP256);
    assert_eq!(info.sequence(), 1);
    assert_eq!(info.origin(), &ObjectOrigin::WrappedGenerated);

    // Cleanup
    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete restored target key");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
    assert!(session.get_object_info(wrap_id, ObjectType::WrapKey).is_err(), "Deleted wrap key should not be retrievable");
}

// ════════════════════════════════════════════════════════════════
//  E.2 — AES CCM: export multiple objects at once
// ════════════════════════════════════════════════════════════════
#[test]
fn test_aes_wrap_export_multiple_objects() {
    let (_h, session) = open_session();

    let wrap_id = generate_aes_wrap_key(&session);
    let target_id_1 = generate_target_key(&session);
    let target_id_2 = generate_target_key(&session);

    let op_spec = aes_wrap_op_spec(wrap_id);
    let export_objects = vec![
        ObjectHandle { object_id: target_id_1, object_type: ObjectType::AsymmetricKey },
        ObjectHandle { object_id: target_id_2, object_type: ObjectType::AsymmetricKey },
    ];
    let wrapped_list = WrapOperations::export_wrapped(&session, &op_spec, &export_objects)
                                     .expect("Exporting multiple objects should succeed");
    assert_eq!(wrapped_list.len(), 2, "Should have two wrapped objects");

    session.delete_object(target_id_1, ObjectType::AsymmetricKey).expect("Failed to delete original object 1");
    session.delete_object(target_id_2, ObjectType::AsymmetricKey).expect("Failed to delete original object 2");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
}

// ════════════════════════════════════════════════════════════════
//  E.3 — Error: export with wrong wrap key ID
// ════════════════════════════════════════════════════════════════
#[test]
fn test_aes_wrap_export_with_wrong_wrapkey_fails() {
    let (_h, session) = open_session();
    let bad_wrap_id = 0xFFFF; // non-existent wrap key

    let target_id = generate_target_key(&session);

    let op_spec = aes_wrap_op_spec(bad_wrap_id);
    let export_objects = vec![ObjectHandle {
        object_id: target_id,
        object_type: ObjectType::AsymmetricKey,
    }];

    let wrapped = WrapOperations::export_wrapped(&session, &op_spec, &export_objects).expect("Export should succeed even with wrong wrap key ID (error is deferred to wrapped object)");
    assert!(wrapped[0].error.is_some(), "Export with non-existent wrap key should fail");

    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete target key");
}

// ════════════════════════════════════════════════════════════════
//  E.4 — Error: export object that doesn't exist
// ════════════════════════════════════════════════════════════════
#[test]
fn test_aes_wrap_export_nonexistent_object_fails() {
    let (_h, session) = open_session();

    let wrap_id = generate_aes_wrap_key(&session);
    let target_id = generate_target_key(&session);

    let op_spec = aes_wrap_op_spec(wrap_id);
    let export_objects = vec![
        ObjectHandle {
            object_id: target_id,
            object_type: ObjectType::AsymmetricKey,
        },
        ObjectHandle {
            object_id: 0xFFFE, // non-existent
            object_type: ObjectType::AsymmetricKey,
    }];
    let wrapped = WrapOperations::export_wrapped(&session, &op_spec, &export_objects)
        .expect("Export should succeed even if one object doesn't exist (error is deferred to wrapped objects)");
    assert_eq!(wrapped.len(), 2, "Should have two wrapped objects");
    assert!(wrapped[0].error.is_none(), "Export of existing object should succeed");
    assert!(wrapped[1].error.is_some(), "Export of non-existent object should fail");

    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete target key");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
}

// ════════════════════════════════════════════════════════════════
//  E.5 — Error: export object without ExportableUnderWrap
// ════════════════════════════════════════════════════════════════
#[test]
fn test_aes_wrap_export_without_exportable_capability_fails() {
    let (_h, session) = open_session();

    let wrap_id = generate_aes_wrap_key(&session);

    // Generate a key WITHOUT ExportableUnderWrap
    let target_spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::AsymmetricKey,
        label: "nonexportable".to_string(),
        algorithm: ObjectAlgorithm::EcP256,
        domains: vec![ObjectDomain::One],
        capabilities: vec![ObjectCapability::SignEcdsa], // no ExportableUnderWrap
        delegated_capabilities: vec![],
        data: vec![],
    };
    let target_id = AsymmetricOperations.generate(&session, &target_spec).expect("Failed to generate target key without ExportableUnderWrap");

    let wrap_spec = aes_wrap_op_spec(wrap_id);
    let export_objects = vec![ObjectHandle {
        object_id: target_id,
        object_type: ObjectType::AsymmetricKey,
    }];
    let wrapped = WrapOperations::export_wrapped(&session, &wrap_spec, &export_objects)
        .expect("Export should succeed even if object lacks ExportableUnderWrap (error is deferred to wrapped object)");
    assert!(
        wrapped[0].error.is_some(),
        "Export should fail when object lacks ExportableUnderWrap"
    );

    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete target key");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
}

// ════════════════════════════════════════════════════════════════
//  E.6 — RSA-OAEP: export and import a single object
// ════════════════════════════════════════════════════════════════
#[test]
fn test_rsa_wrap_object() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 4, 0) {
        eprintln!("Skipping RSA wrap test: requires firmware 2.4.0 or later");
        return;
    }

    // Generate RSA wrap key pair (private + public)
    let wrap_id = generate_rsa_wrap_key_pair(&session);
    let target_id = generate_target_key(&session);
    let target_info = session.get_object_info(target_id, ObjectType::AsymmetricKey).expect("Failed to get object info for target key");
    assert_eq!(target_info.sequence(), 0);
    assert_eq!(target_info.origin(), &ObjectOrigin::Generated);

    // Export using public wrap key
    let mut op_spec = rsa_wrap_op_spec(wrap_id, WrapKeyType::RsaPublic, WrapType::Object);
    let export_objects = vec![ObjectHandle {
        object_id: target_id,
        object_type: ObjectType::AsymmetricKey,
    }];
    let wrapped = WrapOperations::export_wrapped(&session, &op_spec, &export_objects)
                                .expect("RSA-OAEP export_wrapped should succeed");
    assert_eq!(wrapped.len(), 1);
    assert!(wrapped[0].error.is_none(), "Export should succeed without error: {:?}", wrapped[0].error.as_ref());

    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete original object");

    // Import using private wrap key
    op_spec.wrapkey_type = WrapKeyType::Rsa;
    let handle = WrapOperations::import_wrapped(
        &session, &op_spec, &wrapped[0].wrapped_data, None,
    ).expect("RSA-OAEP import_wrapped should succeed");
    assert_eq!(handle.object_id, target_id);
    assert_eq!(handle.object_type, *target_info.object_type());
    let imported_info = session.get_object_info(handle.object_id, handle.object_type).expect("Failed to get object info for imported object");
    assert_eq!(imported_info.sequence(), 1);
    assert_eq!(imported_info.origin(), &ObjectOrigin::WrappedGenerated);

    // Cleanup
    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete target key");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
    session.delete_object(wrap_id, ObjectType::PublicWrapKey).expect("Failed to delete public wrap key");
}

// ════════════════════════════════════════════════════════════════
//  E.7 — RSA-OAEP: export and import a single object
// ════════════════════════════════════════════════════════════════
#[test]
fn test_rsa_wrap_key() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 4, 0) {
        eprintln!("Skipping RSA wrap test: requires firmware 2.4.0 or later");
        return;
    }

    // Generate RSA wrap key pair (private + public)
    let wrap_id = generate_rsa_wrap_key_pair(&session);
    let target_id = generate_target_key(&session);
    let target_info = session.get_object_info(target_id, ObjectType::AsymmetricKey).expect("Failed to get object info for target key");
    assert_eq!(target_info.sequence(), 0);
    assert_eq!(target_info.origin(), &ObjectOrigin::Generated);

    // Export using public wrap key
    let mut op_spec = rsa_wrap_op_spec(wrap_id, WrapKeyType::RsaPublic, WrapType::Key);
    let export_objects = vec![ObjectHandle {
        object_id: target_id,
        object_type: ObjectType::AsymmetricKey,
    }];
    let wrapped = WrapOperations::export_wrapped(&session, &op_spec, &export_objects)
        .expect("RSA-OAEP export_wrapped should succeed");
    assert_eq!(wrapped.len(), 1);
    assert!(wrapped[0].error.is_none(), "Export should succeed without error: {:?}", wrapped[0].error.as_ref());

    let new_wrapped_spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::AsymmetricKey,
        label: "wrapped".to_string(),
        algorithm: *target_info.algorithm(), // reuse target's algorithm for simplicity
        domains: vec![ObjectDomain::One],
        capabilities: vec![
            ObjectCapability::SignEcdsa,
        ],
        delegated_capabilities: vec![],
        data: vec![],
    };

    // Import using private wrap key
    op_spec.wrapkey_type = WrapKeyType::Rsa;
    let handle = WrapOperations::import_wrapped(
        &session, &op_spec, &wrapped[0].wrapped_data, Some(new_wrapped_spec),
    ).expect("RSA-OAEP import_wrapped should succeed");
    let imported_info = session.get_object_info(handle.object_id, handle.object_type).expect("Failed to get object info for imported object");
    assert_ne!(handle.object_id, target_id, "Imported object should have new ID");
    assert_eq!(imported_info.sequence(), 0);
    assert_eq!(imported_info.origin(), &ObjectOrigin::WrappedImported);

    assert!(session.get_object_info(target_id, ObjectType::AsymmetricKey).is_ok(), "Original target key should still exist after import");

    // Cleanup
    session.delete_object(target_id, ObjectType::AsymmetricKey).expect("Failed to delete target key");
    session.delete_object(handle.object_id, handle.object_type).expect("Failed to delete imported object");
    session.delete_object(wrap_id, ObjectType::WrapKey).expect("Failed to delete wrap key");
    session.delete_object(wrap_id, ObjectType::PublicWrapKey).expect("Failed to delete public wrap key");
}