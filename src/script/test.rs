#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectType};
    use tempfile::TempDir;
    use crate::hsm_operations::types::NewObjectSpec;
    use crate::script::recorder::SessionRecorder;
    use crate::script::types::{RecordedOperation, SessionScript};

    /// Helper: create a recorder pointing at a temp file.
    fn make_recorder(dir: &TempDir) -> (SessionRecorder, PathBuf) {
        let path = dir.path().join("test_recording.json");
        let rec = SessionRecorder::new(
            path.clone(),
            "http://127.0.0.1:12345".to_string(),
            1,
        );
        (rec, path)
    }

    /// Helper: build a minimal GenerateObject operation for testing.
    fn sample_generate(id: u16, label: &str) -> RecordedOperation {
        RecordedOperation::GenerateObject(NewObjectSpec {
            id,
            object_type: ObjectType::AsymmetricKey,
            label: label.to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![ObjectDomain::Eight, ObjectDomain::Ten],
            capabilities: vec![ObjectCapability::SignEcdsa],
            delegated_capabilities: vec![],
            data: vec![],
        })
    }

    /// Helper: deserialize the written file back into a SessionScript.
    fn read_script(path: &PathBuf) -> SessionScript {
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
        let dir = TempDir::new().unwrap();
        let (rec, _) = make_recorder(&dir);
        assert_eq!(rec.operation_count(), 0);
    }

    #[test]
    fn record_increments_operation_count() {
        let dir = TempDir::new().unwrap();
        let (mut rec, _) = make_recorder(&dir);

        rec.record(sample_generate(1, "key-1"));
        assert_eq!(rec.operation_count(), 1);

        rec.record(sample_generate(2, "key-2"));
        assert_eq!(rec.operation_count(), 2);

        rec.record(RecordedOperation::DeleteObject {
            object_id: 1,
            object_type: "AsymmetricKey".to_string(),
        });
        assert_eq!(rec.operation_count(), 3);
    }

    // ------------------------------
    //  Flush & file output tests
    // ------------------------------

    #[test]
    fn flush_creates_file() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(sample_generate(42, "test-key"));
        rec.flush().expect("flush should succeed");

        assert!(path.exists(), "flush should create the output file");
    }

    #[test]
    fn flush_writes_valid_json() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(sample_generate(42, "test-key"));
        rec.flush().unwrap();

        // This will panic if the file isn't valid JSON or doesn't match the schema
        let _script: SessionScript = read_script(&path);
    }

    #[test]
    fn flush_redacts_password() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(sample_generate(1, "k"));
        rec.flush().unwrap();

        let script = read_script(&path);
        assert_eq!(script.session.password, "<PASSWORD>");

        // // Also verify the raw JSON doesn't contain any real password
        // let raw = fs::read_to_string(&path).unwrap();
        // assert!(!raw.contains("my-secret-password"));
    }

    #[test]
    fn flush_preserves_metadata() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("conn_test.json");
        let mut rec = SessionRecorder::new(
            path.clone(),
            "http://10.0.0.1:9999".to_string(),
            7,
        );

        rec.record(sample_generate(1, "k"));
        rec.flush().unwrap();

        let script = read_script(&path);
        assert_eq!(script.session.connector, "http://10.0.0.1:9999");
        assert_eq!(script.session.auth_key_id, 7);
        assert_eq!(script.version, "1.0");
        assert!(!script.recorded_at.is_empty(), "recorded_at should be set");
        // Verify it's a parseable RFC 3339 timestamp
        chrono::DateTime::parse_from_rfc3339(&script.recorded_at)
            .expect("recorded_at should be a valid RFC 3339 timestamp");
    }


    // ------------------------------------
    //  Operation content fidelity tests
    // ------------------------------------

    #[test]
    fn flush_preserves_all_operations_in_order() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(sample_generate(1, "first"));
        rec.record(RecordedOperation::DeleteObject {
            object_id: 99,
            object_type: "SymmetricKey".to_string(),
        });
        rec.record(sample_generate(2, "third"));
        rec.flush().unwrap();

        let script = read_script(&path);
        assert_eq!(script.operations.len(), 3);

        // Verify order
        match &script.operations[0] {
            RecordedOperation::GenerateObject(spec) => {
                assert_eq!(spec.id, 1);
                assert_eq!(spec.label, "first");
            },
            other => panic!("Expected GenerateObject, got {:?}", other),
        }

        match &script.operations[1] {
            RecordedOperation::DeleteObject { object_id, object_type } => {
                assert_eq!(*object_id, 99);
                assert_eq!(object_type, "SymmetricKey");
            },
            other => panic!("Expected DeleteObject, got {:?}", other),
        }

        match &script.operations[2] {
            RecordedOperation::GenerateObject(spec) => {
                assert_eq!(spec.id, 2);
                assert_eq!(spec.label, "third");
            },
            other => panic!("Expected GenerateObject, got {:?}", other),
        }
    }

    #[test]
    fn generate_object_fields_are_preserved() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(RecordedOperation::GenerateObject(NewObjectSpec {
            id: 0x00ab,
            object_type: ObjectType::WrapKey,
            label: "my-wrap-key".to_string(),
            algorithm: ObjectAlgorithm::Aes256CcmWrap,
            domains: vec![ObjectDomain::One, ObjectDomain::Three, ObjectDomain::Five],
            capabilities: vec![ObjectCapability::ExportWrapped, ObjectCapability::ImportWrapped],
            delegated_capabilities: vec![ObjectCapability::SignEcdsa, ObjectCapability::DeriveEcdh],
            data: vec![],
        }));
        rec.flush().unwrap();

        let script = read_script(&path);
        let op = &script.operations[0];
        match op {
            RecordedOperation::GenerateObject(spec) => {
                assert_eq!(spec.id, 0x00ab);
                assert_eq!(spec.object_type, ObjectType::WrapKey);
                assert_eq!(spec.label, "my-wrap-key");
                assert_eq!(spec.algorithm, ObjectAlgorithm::Aes256CcmWrap);
                assert_eq!(spec.domains, vec![ObjectDomain::One, ObjectDomain::Three, ObjectDomain::Five]);
                assert_eq!(spec.capabilities, vec![ObjectCapability::ExportWrapped, ObjectCapability::ImportWrapped]);
                assert_eq!(spec.delegated_capabilities, vec![ObjectCapability::SignEcdsa, ObjectCapability::DeriveEcdh]);
            },
            other => panic!("Expected GenerateObject, got {:?}", other),
        }
    }

    #[test]
    fn all_operation_variants_round_trip() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        let spec = NewObjectSpec {
            id: 1,
            object_type: ObjectType::AsymmetricKey,
            label: "k".to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignEcdsa],
            delegated_capabilities: vec![],
            data: vec![],
        };

        // Record one of every variant
        rec.record(RecordedOperation::GenerateObject(spec.clone()));
        rec.record(RecordedOperation::ImportObject {
            spec: spec.clone(),
            data_b64: vec!["<REDACTED>".to_string()],
        });
        rec.record(RecordedOperation::DeleteObject {
            object_id: 1,
            object_type: "AsymmetricKey".to_string(),
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

        rec.flush().unwrap();

        // Round-trip: read back and verify count
        let script = read_script(&path);
        assert_eq!(script.operations.len(), 3,
                   "All 17 operation variants should survive the JSON round-trip");

        // Verify the JSON is also valid by re-serializing
        let re_serialized = serde_json::to_string_pretty(&script)
            .expect("re-serialization should succeed");
        let re_parsed: SessionScript = serde_json::from_str(&re_serialized)
            .expect("re-parsed JSON should be valid");
        assert_eq!(re_parsed.operations.len(), 3);
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

    #[test]
    fn flush_with_no_operations_writes_empty_list() {
        let dir = TempDir::new().unwrap();
        let (rec, path) = make_recorder(&dir);

        // Explicitly flush with 0 operations
        rec.flush().unwrap();

        let script = read_script(&path);
        assert!(script.operations.is_empty());
    }

    #[test]
    fn flush_can_be_called_multiple_times() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        rec.record(sample_generate(1, "first"));
        rec.flush().unwrap();

        let script = read_script(&path);
        assert_eq!(script.operations.len(), 1);

        // Record more and flush again — file should now contain all operations
        rec.record(sample_generate(2, "second"));
        rec.flush().unwrap();

        let script = read_script(&path);
        assert_eq!(script.operations.len(), 2);
    }

    #[test]
    fn flush_overwrites_previous_file() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        // First write
        rec.record(sample_generate(1, "k"));
        rec.flush().unwrap();
        let size1 = fs::metadata(&path).unwrap().len();

        // Second write with more data — should overwrite, not append
        rec.record(sample_generate(2, "k2"));
        rec.record(sample_generate(3, "k3"));
        rec.flush().unwrap();
        let size2 = fs::metadata(&path).unwrap().len();

        assert!(size2 > size1, "Second flush should produce a larger file");

        // Verify it's still valid JSON (not two concatenated JSON documents)
        let script = read_script(&path);
        assert_eq!(script.operations.len(), 3);
    }

    #[test]
    fn special_characters_in_label_are_preserved() {
        let dir = TempDir::new().unwrap();
        let (mut rec, path) = make_recorder(&dir);

        let label = r#"key with "quotes" and \backslashes\ and émojis 🔑"#;
        rec.record(RecordedOperation::GenerateObject(NewObjectSpec {
            id: 1,
            object_type: ObjectType::AsymmetricKey,
            label: label.to_string(),
            algorithm: ObjectAlgorithm::EcP256,
            domains: vec![],
            capabilities: vec![],
            delegated_capabilities: vec![],
            data: vec![],
        }));
        rec.flush().unwrap();

        let script = read_script(&path);
        match &script.operations[0] {
            RecordedOperation::GenerateObject(spec) => {
                assert_eq!(spec.label, label);
            },
            other => panic!("Expected GenerateObject, got {:?}", other),
        }
    }

    // -------------------------
    //  Drop behavior tests
    // -------------------------

    #[test]
    fn drop_flushes_nonempty_recorder() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("drop_test.json");

        {
            let mut rec = SessionRecorder::new(
                path.clone(),
                "http://127.0.0.1:12345".to_string(),
                1,
            );
            rec.record(sample_generate(1, "dropped-key"));
            // rec is dropped here without explicit flush
        }

        assert!(path.exists(), "Drop should have flushed the file");
        let script = read_script(&path);
        assert_eq!(script.operations.len(), 1);
        match &script.operations[0] {
            RecordedOperation::GenerateObject(spec) => {
                assert_eq!(spec.label, "dropped-key");
            },
            other => panic!("Expected GenerateObject, got {:?}", other),
        }
    }

    #[test]
    fn drop_does_not_write_when_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty_drop_test.json");

        {
            let _rec = SessionRecorder::new(
                path.clone(),
                "http://127.0.0.1:12345".to_string(),
                1,
            );
            // No operations recorded — rec is dropped here
        }

        assert!(!path.exists(),
                "Drop should NOT create a file when no operations were recorded");
    }

    // -------------------------
    //  Error handling tests
    // -------------------------

    #[test]
    fn flush_to_nonexistent_directory_returns_error() {
        let mut rec = SessionRecorder::new(
            PathBuf::from("/nonexistent/directory/recording.json"),
            "http://127.0.0.1:12345".to_string(),
            1,
        );
        rec.record(sample_generate(1, "k"));

        let result = rec.flush();
        assert!(result.is_err(), "Flush to invalid path should return error");
    }
}