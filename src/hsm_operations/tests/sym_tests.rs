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
use crate::hsm_operations::sym::{
    AesMode, AesOperationSpec, EncryptionMode, SymmetricOperations,
};
use crate::hsm_operations::asym::AsymmetricOperations;
use crate::common::types::NewObjectSpec;
use crate::traits::operation_traits::YubihsmOperations;
use openssl::symm::{Cipher, decrypt as ossl_decrypt, encrypt as ossl_encrypt};

/// Build a NewObjectSpec for a symmetric (AES) key with raw key bytes.
pub fn make_sym_spec(
    id: u16,
    label: &str,
    algorithm: ObjectAlgorithm,
    capabilities: Vec<ObjectCapability>,
    key_data: Vec<u8>,
) -> NewObjectSpec {
    NewObjectSpec {
        id,
        object_type: ObjectType::SymmetricKey,
        label: label.to_string(),
        algorithm,
        domains: vec![ObjectDomain::One],
        capabilities,
        delegated_capabilities: vec![],
        data: vec![key_data],
    }
}

// ════════════════════════════════════════════════════════════════
//  C.1 — Generate
// ════════════════════════════════════════════════════════════════

#[test]
fn test_generate_aes128() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-aes128", ObjectAlgorithm::Aes128,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap], vec![]
    );

    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-128 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-128 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes128);
    assert_eq!(desc.object_type, ObjectType::SymmetricKey);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-128 key");
    assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted AES-128 key should no longer be retrievable");
}

#[test]
fn test_generate_aes192() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-aes192", ObjectAlgorithm::Aes192,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap], vec![]
    );

    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-192 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-192 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes192);
    assert_eq!(desc.object_type, ObjectType::SymmetricKey);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-192 key");
    assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted AES-192 key should no longer be retrievable");
}

#[test]
fn test_generate_aes256() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-aes256", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap], vec![]
    );

    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes256);
    assert_eq!(desc.object_type, ObjectType::SymmetricKey);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key");
    assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted AES-256 key should no longer be retrievable");
}

#[test]
fn test_generate_duplicate_id_fails() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let mut spec = make_sym_spec(
        0, "test-dup-sym", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb], vec![]
    );

    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate symmetric key for duplicate ID test");
    spec.id = id;
    let result = SymmetricOperations.generate(&session, &spec);
    assert!(result.is_err(), "Duplicate ID should fail");

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated symmetric key for duplicate ID test");
}

// ════════════════════════════════════════════════════════════════
//  C.2 — Import
// ══════════════════════════════════════════════════════════════��═

#[test]
fn test_import_aes128() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0x42u8; 16]; // 128-bit key
    let spec = make_sym_spec(
        0, "test-import-aes128", ObjectAlgorithm::Aes128,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap],
        key_bytes,
    );

    let id = SymmetricOperations.import(&session, &spec).expect("Failed to import AES-128 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for imported AES-128 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes128);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete imported AES-128 key");
    assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted imported AES-128 key should no longer be retrievable");
}

#[test]
fn test_import_aes192() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0x42u8; 24]; // 192-bit key
    let spec = make_sym_spec(
        0, "test-import-aes192", ObjectAlgorithm::Aes192,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap],
        key_bytes,
    );

    let id = SymmetricOperations.import(&session, &spec).expect("Failed to import AES-192 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for imported AES-128 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes192);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete imported AES-192 key");
        assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted imported AES-192 key should no longer be retrievable");
}

#[test]
fn test_import_aes256() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0xABu8; 32]; // 256-bit key
    let spec = make_sym_spec(
        0, "test-import-aes256", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap],
        key_bytes,
    );

    let id = SymmetricOperations.import(&session, &spec).expect("Failed to import AES-256 key");
    let desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for imported AES-256 key");
    assert_eq!(desc.algorithm, ObjectAlgorithm::Aes256);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete imported AES-256 key");
    assert!(session.get_object_info(id, ObjectType::SymmetricKey).is_err(), "Deleted imported AES-256 key should no longer be retrievable");
}

#[test]
fn test_import_wrong_keylen_fails() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0xFFu8; 17]; // invalid: not 16, 24, or 32
    let spec = make_sym_spec(
        0, "test-import-bad", ObjectAlgorithm::Aes128,
        vec![ObjectCapability::EncryptEcb],
        key_bytes,
    );

    assert!(SymmetricOperations.import(&session, &spec).is_err(), "Importing with wrong key length should fail");
}

// ════════════════════════════════════════════════════════════════
//  C.3 — ECB Encrypt / Decrypt round-trip
// ════════════════════════════════════════════════════════════════

/// Helper: build an AesOperationSpec for a given key descriptor.
fn make_op_spec(
    key_desc: ObjectDescriptor,
    aes_mode: AesMode,
    enc_mode: EncryptionMode,
    iv: Vec<u8>,
    data: Vec<u8>,
) -> AesOperationSpec {
    AesOperationSpec {
        operation_key: key_desc,
        aes_mode,
        enc_mode,
        iv,
        data,
    }
}

#[test]
fn test_ecb_encrypt_decrypt_roundtrip_aes256() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-ecb-rt", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for ECB round-trip test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key for ECB round-trip test");

    // ECB plaintext must be a multiple of 16 bytes (AES block size)
    let plaintext = b"0123456789ABCDEF".to_vec(); // exactly 16 bytes

    // Encrypt
    let op_spec = make_op_spec(
        key_desc.clone(), AesMode::Ecb, EncryptionMode::Encrypt, vec![], plaintext.clone(),
    );
    let ciphertext = SymmetricOperations::operate(&session, op_spec).expect("ECB encryption failed");
    assert_eq!(ciphertext.len(), 16, "ECB ciphertext should be same length as plaintext");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");

    // Decrypt
    let op_spec = make_op_spec(
        key_desc, AesMode::Ecb, EncryptionMode::Decrypt, vec![], ciphertext,
    );
    let decrypted = SymmetricOperations::operate(&session, op_spec).expect("ECB decryption failed");
    assert_eq!(decrypted, plaintext, "Decrypted data should match original plaintext");

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for ECB round-trip test");
}

#[test]
fn test_ecb_multi_block() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-ecb-multi", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for ECB multi-block test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key for ECB multi-block test");

    // 3 blocks = 48 bytes
    let plaintext = vec![0xAAu8; 48];

    let op_spec = make_op_spec(
        key_desc.clone(), AesMode::Ecb, EncryptionMode::Encrypt, vec![], plaintext.clone(),
    );
    let ciphertext = SymmetricOperations::operate(&session, op_spec).expect("ECB encryption failed for multi-block test");
    assert_eq!(ciphertext.len(), 48);

    let op_spec = make_op_spec(
        key_desc, AesMode::Ecb, EncryptionMode::Decrypt, vec![], ciphertext,
    );
    let decrypted = SymmetricOperations::operate(&session, op_spec).expect("ECB decryption failed for multi-block test");
    assert_eq!(decrypted, plaintext);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for ECB multi-block test");
}

// ════════════════════════════════════════════════════════════════
//  C.4 — CBC Encrypt / Decrypt round-trip
// ═════════════════════════════════��══════════════════════════════

#[test]
fn test_cbc_encrypt_decrypt_roundtrip_aes256() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-cbc-rt", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for CBC round-trip test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key for CBC round-trip test");

    let iv = vec![0x00u8; 16]; // 16-byte IV for AES-CBC
    let plaintext = b"CBC test block!!".to_vec(); // exactly 16 bytes

    // Encrypt
    let op_spec = make_op_spec(
        key_desc.clone(), AesMode::Cbc, EncryptionMode::Encrypt, iv.clone(), plaintext.clone(),
    );
    let ciphertext = SymmetricOperations::operate(&session, op_spec).expect("CBC encryption failed");
    assert_ne!(ciphertext, plaintext, "Ciphertext should differ from plaintext");

    // Decrypt with same IV
    let op_spec = make_op_spec(
        key_desc, AesMode::Cbc, EncryptionMode::Decrypt, iv, ciphertext,
    );
    let decrypted = SymmetricOperations::operate(&session, op_spec).expect("CBC decryption failed");
    assert_eq!(decrypted, plaintext, "CBC decrypted data should match original");

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for CBC round-trip test");
}

#[test]
fn test_cbc_multi_block() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-cbc-multi", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for CBC multi-block test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key for CBC multi-block test");

    let iv = vec![0x37u8; 16];
    let plaintext = vec![0xBBu8; 64]; // 4 blocks

    let op_spec = make_op_spec(
        key_desc.clone(), AesMode::Cbc, EncryptionMode::Encrypt, iv.clone(), plaintext.clone(),
    );
    let ciphertext = SymmetricOperations::operate(&session, op_spec).unwrap();
    assert_eq!(ciphertext.len(), 64);

    let op_spec = make_op_spec(
        key_desc, AesMode::Cbc, EncryptionMode::Decrypt, iv, ciphertext,
    );
    let decrypted = SymmetricOperations::operate(&session, op_spec).unwrap();
    assert_eq!(decrypted, plaintext);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for CBC multi-block test");
}

#[test]
fn test_cbc_wrong_iv_produces_wrong_plaintext() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-cbc-wrongiv", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for CBC wrong IV test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for generated AES-256 key for CBC wrong IV test");

    let iv_enc = vec![0x00u8; 16];
    let iv_dec = vec![0xFFu8; 16]; // different IV
    let plaintext = b"wrong IV test!!!".to_vec();

    let op_spec = make_op_spec(
        key_desc.clone(), AesMode::Cbc, EncryptionMode::Encrypt, iv_enc, plaintext.clone(),
    );
    let ciphertext = SymmetricOperations::operate(&session, op_spec).expect("CBC encryption failed for wrong IV test");

    // Decrypt with wrong IV — should succeed but produce wrong plaintext
    let op_spec = make_op_spec(
        key_desc, AesMode::Cbc, EncryptionMode::Decrypt, iv_dec, ciphertext,
    );
    let decrypted = SymmetricOperations::operate(&session, op_spec).expect("CBC decryption failed for wrong IV test");
    assert_ne!(
        decrypted, plaintext,
        "Decrypting with wrong IV should not produce original plaintext"
    );

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for CBC wrong IV test");
}

// ════════════════════════════════════════════════════════════════
//  C.5 — Import known key → encrypt → verify with OpenSSL
// ════════════════════════════════════════════════════════════════

#[test]
fn test_import_known_key_ecb_matches_openssl() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0x01u8; 32]; // known AES-256 key
    let spec = make_sym_spec(
        0, "test-ecb-ossl", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::DecryptEcb,
             ObjectCapability::ExportableUnderWrap],
        key_bytes.clone(),
    );
    let id = SymmetricOperations.import(&session, &spec).expect("Failed to import AES-256 key for OpenSSL ECB test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for imported AES-256 key for OpenSSL ECB test");
    let plaintext = b"OpenSSL ECB test".to_vec(); // 16 bytes

    // Encrypt on YubiHSM
    let op_spec = make_op_spec(
        key_desc, AesMode::Ecb, EncryptionMode::Encrypt, vec![], plaintext.clone(),
    );
    let hsm_ciphertext = SymmetricOperations::operate(&session, op_spec).expect("YubiHSM ECB encryption failed for OpenSSL comparison test");

    // Encrypt same data with OpenSSL using same key (no padding — data is already block-aligned)
    let ossl_ciphertext = ossl_encrypt(
        Cipher::aes_256_ecb(), &key_bytes, None, &plaintext,
    ).expect("OpenSSL encryption failed for ECB comparison test");

    // OpenSSL with default padding appends a full padding block. Compare only the first 16 bytes.
    assert_eq!(
        hsm_ciphertext, ossl_ciphertext[..16],
        "YubiHSM ECB ciphertext should match OpenSSL for the same key and plaintext"
    );

    // Also verify: decrypt OpenSSL ciphertext with OpenSSL to confirm correctness
    let ossl_decrypted = ossl_decrypt(
        Cipher::aes_256_ecb(), &key_bytes, None, &ossl_ciphertext,
    ).expect("OpenSSL decryption failed for ECB comparison test");
    assert_eq!(ossl_decrypted, plaintext);

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete imported AES-256 key for OpenSSL ECB test");
}

#[test]
fn test_import_known_key_cbc_matches_openssl() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let key_bytes = vec![0x02u8; 32];
    let iv = vec![0x03u8; 16];
    let spec = make_sym_spec(
        0, "test-cbc-ossl", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::DecryptCbc,
             ObjectCapability::ExportableUnderWrap],
        key_bytes.clone(),
    );
    let id = SymmetricOperations.import(&session, &spec).expect("Failed to import AES-256 key for OpenSSL CBC test");
    let key_desc = session.get_object_info(id, ObjectType::SymmetricKey).expect("Failed to get object info for imported AES-256 key for OpenSSL CBC test");
    let plaintext = b"OpenSSL CBC test".to_vec(); // 16 bytes

    // Encrypt on YubiHSM
    let op_spec = make_op_spec(
        key_desc, AesMode::Cbc, EncryptionMode::Encrypt, iv.clone(), plaintext.clone(),
    );
    let hsm_ciphertext = SymmetricOperations::operate(&session, op_spec).expect("YubiHSM CBC encryption failed for OpenSSL comparison test");

    // Encrypt with OpenSSL (same key, same IV)
    let ossl_ciphertext = ossl_encrypt(
        Cipher::aes_256_cbc(), &key_bytes, Some(&iv), &plaintext,
    ).expect("OpenSSL encryption failed for CBC comparison test");

    // OpenSSL default padding adds 16 bytes. Compare first block.
    assert_eq!(
        hsm_ciphertext, ossl_ciphertext[..16],
        "YubiHSM CBC ciphertext should match OpenSSL for same key/IV/plaintext"
    );

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete imported AES-256 key for OpenSSL CBC test");
}

// ════════════════════════════════════════════════════════════════
//  C.6 — Listing
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_all_sym_objects() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-list-sym", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for listing test");

    let ec_spec = NewObjectSpec {
        id: 0,
        object_type: ObjectType::AsymmetricKey,
        label: "test-list-ec".to_string(),
        algorithm: ObjectAlgorithm::EcP256,
        domains: vec![ObjectDomain::One],
        capabilities: vec![ObjectCapability::SignEcdsa],
        delegated_capabilities: vec![],
        data: vec![],
    };
    let ec_id = AsymmetricOperations.generate(&session, &ec_spec).expect("Failed to generate EC key for listing test");

    let objects = SymmetricOperations.get_all_objects(&session).expect("Failed to get all objects for listing test");
    assert!(
        objects.iter().any(|o| o.id == id),
        "Generated AES key should appear in get_all_objects"
    );
    assert!(
        !objects.iter().any(|o| o.id == ec_id),
        "Generated asymmetric key should not appear in get_all_objects"
    );

    session.delete_object(id, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key for listing test");
    session.delete_object(ec_id, ObjectType::AsymmetricKey).expect("Failed to delete generated EC key for listing test");
}

// ════════════════════════════════════════════════════════════════
//  C.7 — get_operation_keys filtering
// ════════════════════════════════════════════════════════════════

#[test]
fn test_get_operation_keys_encrypt_ecb() {
    let (hsm, session) = open_session();
    if !is_firmware_compatible(&hsm, 2, 3, 0) {
        eprintln!("Skipping Symmetric Key test: requires firmware 2.3.0 or later");
        return;
    }
    let spec = make_sym_spec(
        0, "test-opkeys-ecb", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptEcb, ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id_1 = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key for operation keys test (ECB)");

    let spec = make_sym_spec(
        0, "test-opkeys-ecb", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::DecryptEcb, ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id_2 = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key without decryption capabilities for operation keys test (ECB)");

    let spec = make_sym_spec(
        0, "test-opkeys-ecb", ObjectAlgorithm::Aes256,
        vec![ObjectCapability::EncryptCbc, ObjectCapability::ExportableUnderWrap], vec![]
    );
    let id_3 = SymmetricOperations.generate(&session, &spec).expect("Failed to generate AES-256 key without ECB capabilities for operation keys test (ECB)");


    let authkey = session
        .get_object_info(DEFAULT_AUTHKEY_ID, ObjectType::AuthenticationKey)
        .expect("Failed to get authkey info for operation keys test (ECB)");
    let keys = SymmetricOperations::get_operation_keys(
        &session, &authkey, EncryptionMode::Encrypt, AesMode::Ecb,
    ).expect("Failed to get operation keys for ECB encryption test");
    assert!(
        keys.iter().any(|k| k.id == id_1),
        "ECB-encrypt capable key should appear in operation keys"
    );
    assert!(
        !keys.iter().any(|k| k.id == id_2),
        "Only ECB-decrypt capable key should not appear in operation keys"
    );
    assert!(
        !keys.iter().any(|k| k.id == id_3),
        "Only CBC-encrypt capable key should not appear in operation keys"
    );

    session.delete_object(id_1, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key 1 for operation keys test (ECB)");
    session.delete_object(id_2, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key 2 for operation keys test (ECB)");
    session.delete_object(id_3, ObjectType::SymmetricKey).expect("Failed to delete generated AES-256 key 3 for operation keys test (ECB)");
}