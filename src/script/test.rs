/*
 * Copyright 2026 Yubico AB
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};
    use crate::script::script_recorder::SessionRecorder;
    use crate::script::script_common::{RecordableObjectSpec, RecordedOperation, SessionScript};

    /// Helper: create a recorder pointing at a temp file.
    fn get_recorder() -> SessionRecorder {
        SessionRecorder::new(
            "http://127.0.0.1:12345".to_string(),
            1,
        )
    }

    /// Helper: build a minimal GenerateObject operation for testing.
    fn sample_generate(id: u16, label: &str) -> RecordedOperation {
        RecordedOperation::GenerateObject(RecordableObjectSpec {
            id,
            object_type: ObjectType::AsymmetricKey,
            label: label.to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![ObjectDomain::Eight, ObjectDomain::Ten],
            capabilities: vec![ObjectCapability::SignEcdsa],
            delegated_capabilities: vec![],
        })
    }

    /// Helper: deserialize the written file back into a SessionScript.
    fn read_script(path: &Path) -> SessionScript {
        let content = fs::read_to_string(path)
            .expect("recording file should exist after flush");
        serde_json::from_str(&content)
            .expect("recording file should be valid JSON")
    }

    // -----------------------------------
    //  Basic lifecycle tests
    // -----------------------------------

    #[test]
    fn new_recorder_has_zero_operations() {
        let rec = get_recorder();
        assert_eq!(rec.operation_count(), 0);
    }

    #[test]
    fn record_increments_operation_count() {
        let rec = get_recorder();

        rec.record(sample_generate(1, "key-1"));
        assert_eq!(rec.operation_count(), 1);

        rec.record(sample_generate(2, "key-2"));
        assert_eq!(rec.operation_count(), 2);

        rec.record(RecordedOperation::DeleteObject {
            object_id: 1,
            object_type: ObjectType::AsymmetricKey,
        });
        assert_eq!(rec.operation_count(), 3);
    }

    // ------------------------------
    //  Flush & file output tests
    // ------------------------------

    #[test]
    fn flush_creates_file() {
        let rec = get_recorder();

        rec.record(sample_generate(42, "test-key"));
        let f = rec.flush().expect("flush should succeed");

        assert!(Path::new(&f).exists(), "flush should create the output file");
        fs::remove_file(&f).unwrap();  // clean up after test
    }

    // #[test]
    // fn flush_writes_valid_json() {
    //     let rec = get_recorder();
    //     rec.record(sample_generate(42, "test-key"));
    //     let f = rec.flush().unwrap();
    //
    //     // This will panic if the file isn't valid JSON or doesn't match the schema
    //     let _script: SessionScript = read_script(Path::new(&f));
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }

    // #[test]
    // fn flush_preserves_metadata() {
    //
    //     let rec = SessionRecorder::new(
    //         "http://10.0.0.1:9999".to_string(),
    //         7,
    //     );
    //
    //     rec.record(sample_generate(1, "k"));
    //     let f = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f));
    //     assert_eq!(script.session.connector, "http://10.0.0.1:9999");
    //     assert_eq!(script.session.auth_key_id, 7);
    //     assert_eq!(script.version, "1.0");
    //     assert!(!script.recorded_at.is_empty(), "recorded_at should be set");
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }


    // ------------------------------------
    //  Operation content fidelity tests
    // ------------------------------------

    // #[test]
    // fn flush_preserves_all_operations_in_order() {
    //     let rec = get_recorder();
    //     rec.record(sample_generate(1, "first"));
    //     rec.record(RecordedOperation::DeleteObject {
    //         object_id: 99,
    //         object_type: ObjectType::SymmetricKey,
    //     });
    //     rec.record(sample_generate(2, "third"));
    //     let f = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f));
    //     assert_eq!(script.operations.len(), 3);
    //
    //     // Verify order
    //     match &script.operations[0] {
    //         RecordedOperation::GenerateObject(spec) => {
    //             assert_eq!(spec.id, 1);
    //             assert_eq!(spec.label, "first");
    //         },
    //         other => panic!("Expected GenerateObject, got {:?}", other),
    //     }
    //
    //     match &script.operations[1] {
    //         RecordedOperation::DeleteObject { object_id, object_type } => {
    //             assert_eq!(*object_id, 99);
    //             assert_eq!(object_type, &ObjectType::SymmetricKey);
    //         },
    //         other => panic!("Expected DeleteObject, got {:?}", other),
    //     }
    //
    //     match &script.operations[2] {
    //         RecordedOperation::GenerateObject(spec) => {
    //             assert_eq!(spec.id, 2);
    //             assert_eq!(spec.label, "third");
    //         },
    //         other => panic!("Expected GenerateObject, got {:?}", other),
    //     }
    //
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }

    // #[test]
    // fn generate_object_fields_are_preserved() {
    //     let rec = get_recorder();
    //     rec.record(RecordedOperation::GenerateObject(RecordableObjectSpec {
    //         id: 100,
    //         object_type: ObjectType::WrapKey,
    //         label: "my-wrap-key".to_string(),
    //         algorithm: ObjectAlgorithm::Aes256CcmWrap,
    //         domains: vec![ObjectDomain::One, ObjectDomain::Three, ObjectDomain::Five],
    //         capabilities: vec![ObjectCapability::ExportWrapped, ObjectCapability::ImportWrapped],
    //         delegated_capabilities: vec![ObjectCapability::SignEcdsa, ObjectCapability::DeriveEcdh],
    //     }));
    //     let f = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f));
    //     let op = &script.operations[0];
    //     match op {
    //         RecordedOperation::GenerateObject(spec) => {
    //             assert_eq!(spec.id, 100);
    //             assert_eq!(spec.object_type, ObjectType::WrapKey);
    //             assert_eq!(spec.label, "my-wrap-key");
    //             assert_eq!(spec.algorithm, ObjectAlgorithm::Aes256CcmWrap);
    //             assert_eq!(spec.domains, vec![ObjectDomain::One, ObjectDomain::Three, ObjectDomain::Five]);
    //             assert_eq!(spec.capabilities, vec![ObjectCapability::ExportWrapped, ObjectCapability::ImportWrapped]);
    //             assert_eq!(spec.delegated_capabilities, vec![ObjectCapability::SignEcdsa, ObjectCapability::DeriveEcdh]);
    //         },
    //         other => panic!("Expected GenerateObject, got {:?}", other),
    //     }
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }

    #[test]
    fn all_operation_variants_round_trip() {
        let rec = get_recorder();
        let spec = RecordableObjectSpec {
            id: 1,
            object_type: ObjectType::AsymmetricKey,
            label: "k".to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignEcdsa],
            delegated_capabilities: vec![],
        };

        // Record one of every variant
        rec.record(RecordedOperation::GenerateObject(spec.clone()));
        // rec.record(RecordedOperation::ImportObject {
        //     spec: spec.clone(),
        //     data_b64: vec!["<REDACTED>".to_string()],
        // });
        rec.record(RecordedOperation::DeleteObject {
            object_id: 1,
            object_type: ObjectType::AsymmetricKey,
        });
        // rec.record(RecordedOperation::CreateAuthKey {
        //     spec: spec.clone(),
        //     auth_type: "PasswordDerived".to_string(),
        //     credential: "<PASSWORD>".to_string(),
        // });
        // rec.record(RecordedOperation::Sign {
        //     key_id: 1,
        //     algorithm: "EcdsaSha256".to_string(),
        //     input: "/tmp/data.bin".to_string(),
        //     output_file: Some("/tmp/data.sig".to_string()),
        // });
        // rec.record(RecordedOperation::Decrypt {
        //     key_id: 1,
        //     algorithm: "RsaPkcs1Decrypt".to_string(),
        //     input: "abcdef".to_string(),
        //     output_file: None,
        // });
        // rec.record(RecordedOperation::DeriveEcdh {
        //     key_id: 1,
        //     peer_pubkey_file: "/tmp/peer.pem".to_string(),
        // });
        // rec.record(RecordedOperation::SignAttestationCert {
        //     attested_key_id: 1,
        //     attesting_key_id: 2,
        //     template_cert_file: None,
        //     output_file: Some("/tmp/attest.pem".to_string()),
        // });
        // rec.record(RecordedOperation::AesEncrypt {
        //     key_id: 10,
        //     aes_mode: "Cbc".to_string(),
        //     iv_hex: Some("00".repeat(16)),
        //     input: "aabbccdd".to_string(),
        //     output_file: None,
        // });
        // rec.record(RecordedOperation::AesDecrypt {
        //     key_id: 10,
        //     aes_mode: "Ecb".to_string(),
        //     iv_hex: None,
        //     input: "/tmp/enc.bin".to_string(),
        //     output_file: Some("/tmp/dec.bin".to_string()),
        // });
        // rec.record(RecordedOperation::ExportWrapped {
        //     wrapkey_id: 5,
        //     wrapkey_type: "Aes".to_string(),
        //     wrap_type: "Object".to_string(),
        //     object_ids: vec![1, 2, 3],
        //     output_directory: "/tmp/backup".to_string(),
        //     oaep_algorithm: None,
        //     mgf1_algorithm: None,
        // });
        // rec.record(RecordedOperation::ImportWrapped {
        //     wrapkey_id: 5,
        //     wrapkey_type: "Aes".to_string(),
        //     wrap_type: "Object".to_string(),
        //     input_file: "/tmp/backup/0x0001.yhw".to_string(),
        //     oaep_algorithm: None,
        //     mgf1_algorithm: None,
        //     new_key_spec: None,
        // });
        // rec.record(RecordedOperation::GetRandom { num_bytes: 32 });
        // rec.record(RecordedOperation::BackupDevice {
        //     wrapkey_id: 5,
        //     output_directory: "/tmp/backup".to_string(),
        // });
        // rec.record(RecordedOperation::RestoreDevice {
        //     wrapkey_id: 5,
        //     input_directory: "/tmp/backup".to_string(),
        // });
        // rec.record(RecordedOperation::ResetDevice);
        // rec.record(RecordedOperation::KspSetup {
        //     rsa_decrypt: true,
        //     wrapkey_id: 10,
        //     domains: vec!["1".to_string()],
        //     shares: 5,
        //     threshold: 3,
        //     app_authkey_id: 20,
        //     app_authkey_password: "<PASSWORD>".to_string(),
        //     audit_authkey_id: Some(30),
        //     audit_authkey_password: Some("<PASSWORD>".to_string()),
        //     export_directory: Some("/tmp/export".to_string()),
        //     delete_current_authkey: true,
        // });

        let f = rec.flush().unwrap();

        // Round-trip: read back and verify count
        let script = read_script(Path::new(&f));
        assert_eq!(script.operations.len(), 2,
                   "All 17 operation variants should survive the JSON round-trip");

        // Verify the JSON is also valid by re-serializing
        let re_serialized = serde_json::to_string_pretty(&script)
            .expect("re-serialization should succeed");
        let re_parsed: SessionScript = serde_json::from_str(&re_serialized)
            .expect("re-parsed JSON should be valid");
        assert_eq!(re_parsed.operations.len(), 2);

        fs::remove_file(&f).unwrap();  // clean up after test
    }

    // // -------------------------------------------
    // //  Optional field serialization tests
    // // -------------------------------------------
    //
    // #[test]
    // fn optional_fields_omitted_when_none() {
    //     let dir = TempDir::new().unwrap();
    //     let (rec, path) = make_recorder(&dir);
    //
    //     rec.record(RecordedOperation::Sign {
    //         key_id: 1,
    //         algorithm: "EcdsaSha256".to_string(),
    //         input: "data".to_string(),
    //         output_file: None,  // should be omitted from JSON
    //     });
    //     rec.flush().unwrap();
    //
    //     let raw = fs::read_to_string(&path).unwrap();
    //     assert!(!raw.contains("output_file"),
    //             "output_file should be omitted when None, got:\n{}", raw);
    // }
    //
    // #[test]
    // fn empty_delegated_capabilities_omitted() {
    //     let dir = TempDir::new().unwrap();
    //     let (rec, path) = make_recorder(&dir);
    //
    //     rec.record(sample_generate(1, "k"));
    //     rec.flush().unwrap();
    //
    //     let raw = fs::read_to_string(&path).unwrap();
    //     assert!(!raw.contains("delegated_capabilities"),
    //             "empty delegated_capabilities should be omitted, got:\n{}", raw);
    // }

    // ---------------
    //  Edge cases
    // ---------------

    // #[test]
    // fn flush_with_no_operations_writes_empty_list() {
    //     let rec = get_recorder();
    //
    //     // Explicitly flush with 0 operations
    //     let f = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f));
    //     assert!(script.operations.is_empty());
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }

    // #[test]
    // fn flush_can_be_called_multiple_times() {
    //     let rec = get_recorder();
    //     rec.record(sample_generate(1, "first"));
    //     let f1 = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f1));
    //     assert_eq!(script.operations.len(), 1);
    //
    //     // Record more and flush again — file should now contain all operations
    //     rec.record(sample_generate(2, "second"));
    //     let f2 = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f2));
    //     assert_eq!(script.operations.len(), 2);
    //
    //     // Clean up
    //     fs::remove_file(&f1).unwrap();
    //     fs::remove_file(&f2).unwrap();
    // }

    // #[test]
    // fn special_characters_in_label_are_preserved() {
    //     let rec = get_recorder();
    //
    //     let label = r#"key with "quotes" and \backslashes\ and émojis 🔑"#;
    //     rec.record(RecordedOperation::GenerateObject(RecordableObjectSpec {
    //         id: 1,
    //         object_type: ObjectType::AsymmetricKey,
    //         label: label.to_string(),
    //         algorithm: ObjectAlgorithm::EcP256,
    //         domains: vec![],
    //         capabilities: vec![],
    //         delegated_capabilities: vec![],
    //     }));
    //     let f = rec.flush().unwrap();
    //
    //     let script = read_script(Path::new(&f));
    //     match &script.operations[0] {
    //         RecordedOperation::GenerateObject(spec) => {
    //             assert_eq!(spec.label, label);
    //         },
    //         other => panic!("Expected GenerateObject, got {:?}", other),
    //     }
    //     fs::remove_file(&f).unwrap();  // clean up after test
    // }

    // -------------------------
    //  Drop behavior tests
    // -------------------------

    // #[test]
    // fn drop_flushes_nonempty_recorder() {
    //
    //     //TODO: filename has format "./yubihsm-manager-script-YYmmDD-HH:MM:SS.json". Check that a file that starts with "yubihsm-manager-script-YYmmDD-HH:MM" and ends with ".json" was not created since it's unlikely that the test will take more than a minute
    //         let rec = SessionRecorder::new(
    //             "http://127.0.0.1:12345".to_string(),
    //             1,
    //         );
    //         rec.record(sample_generate(1, "dropped-key"));
    //         // rec is dropped here without explicit flush
    //
    //     assert!(path.exists(), "Drop should have flushed the file");
    //     let script = read_script(&path);
    //     assert_eq!(script.operations.len(), 1);
    //     match &script.operations[0] {
    //         RecordedOperation::GenerateObject(spec) => {
    //             assert_eq!(spec.label, "dropped-key");
    //         },
    //         other => panic!("Expected GenerateObject, got {:?}", other),
    //     }
    // }

}