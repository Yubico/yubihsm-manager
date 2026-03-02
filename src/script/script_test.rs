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
    use tempfile::TempDir;
    use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDomain, ObjectHandle, ObjectType};
    use crate::script::script_types::{RecordableObjectSpec, RecordedOperation, RedactMode};
    use crate::script::backend_json::JsonBackend;
    use crate::script::script_recorder::SessionRecorder;
    use crate::script::script_runner::ScriptRunner;
    use crate::hsm_operations::wrap::{WrapKeyType, WrapOpSpec, WrapType};



// ════════════════════════════════════════════════════════════════
//  1. Full provisioning scenario: Recorder → JSON → load → verify
// ════════════════════════════════════════════════════════════════

    fn make_wrap_op_spec() -> WrapOpSpec {
        WrapOpSpec {
            wrapkey_id: 0x0010,
            wrapkey_type: WrapKeyType::Aes,
            wrap_type: WrapType::Object,
            include_ed_seed: false,
            aes_algorithm: Some(ObjectAlgorithm::Aes256CcmWrap),
            oaep_algorithm: None,
            mgf1_algorithm: None,
        }
    }

    #[test]
    fn test_provisioning_scenario_roundtrip() {
        // let scenario = ProvisioningScenario::build();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("all_variants.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=ABCDEF01".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::None,
            Box::new(JsonBackend),
        );

        rec.record(RecordedOperation::GenerateObject {
            spec: make_base_spec(1, ObjectType::AsymmetricKey, ObjectAlgorithm::Rsa2048),
            context: "asym".to_string(),
        }).unwrap();

        let script = ScriptRunner::load(&path).unwrap();

        assert_eq!(script.version, "1.0");
        assert_eq!(script.session.connector, "yhusb://serial=ABCDEF01");
        assert_eq!(script.session.auth_key_id, 1);
        assert_eq!(script.operations.len(), 1);
    }

    #[test]
    fn test_provisioning_scenario_operation_order() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("all_variants.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=VARIANT1".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::None,
            Box::new(JsonBackend),
        );

        rec.record(RecordedOperation::GenerateObject {
            spec: make_base_spec(1, ObjectType::AsymmetricKey, ObjectAlgorithm::Rsa2048),
            context: "asym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ImportObject {
            spec: make_base_spec(2, ObjectType::AsymmetricKey, ObjectAlgorithm::EcP256),
            value: "/path/to/key.pem".to_string(),
            context: "asym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ImportWrapKey {
            spec: make_base_spec(3, ObjectType::WrapKey, ObjectAlgorithm::Aes256CcmWrap),
            value: "deadbeef".to_string(),
            n_threshold: 2,
            n_shares: 3,
        }).unwrap();

        rec.record(RecordedOperation::DeleteObject {
            object_id: 4,
            object_type: ObjectType::SymmetricKey,
            context: "sym".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::CreateAuthKey {
            spec: RecordableObjectSpec {
                id: 5,
                object_type: ObjectType::AuthenticationKey,
                label: "auth".to_string(),
                algorithm: ObjectAlgorithm::Aes128YubicoAuthentication,
                domains: vec![ObjectDomain::One],
                capabilities: vec![ObjectCapability::PutAuthenticationKey],
                delegated_capabilities: vec![ObjectCapability::SignPkcs],
            },
            credential: "password".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ExportWrapped {
            wrap_spec: make_wrap_op_spec(),
            objects: vec![ObjectHandle { object_id: 1, object_type: ObjectType::AsymmetricKey }],
            destination_directory: "/tmp/export".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::ImportWrapped {
            wrap_spec: make_wrap_op_spec(),
            wrapped_filepath: "/tmp/wrapped.yhw".to_string(),
            new_key_spec: Some(make_base_spec(6, ObjectType::AsymmetricKey, ObjectAlgorithm::Rsa2048)),
        }).unwrap();

        rec.record(RecordedOperation::BackupDevice {
            wrap_spec: make_wrap_op_spec(),
            objects: vec![
                ObjectHandle { object_id: 1, object_type: ObjectType::AsymmetricKey },
                ObjectHandle { object_id: 2, object_type: ObjectType::AsymmetricKey },
            ],
            destination_directory: "/backup".to_string(),
        }).unwrap();

        rec.record(RecordedOperation::RestoreDevice {
            wrap_spec: make_wrap_op_spec(),
            source_directory: "/restore".to_string(),
        }).unwrap();

        let script = ScriptRunner::load(&path).unwrap();
        assert_eq!(script.operations.len(), 9, "All 9 variants must survive the pipeline");

        // Verify the operations are in the exact recording order
        assert!(matches!(&script.operations[0], RecordedOperation::GenerateObject { spec, context }
        if spec.id == 0x0001 && context == "asym"));
        assert!(matches!(&script.operations[1], RecordedOperation::ImportObject { spec, .. }
        if spec.id == 0x0002));
        assert!(matches!(&script.operations[2], RecordedOperation::ImportWrapKey { spec, .. }
        if spec.id == 0x0003 && spec.object_type == ObjectType::WrapKey));
        assert!(matches!(&script.operations[3], RecordedOperation::DeleteObject { object_id, context, .. }
        if *object_id == 0x0004 && context == "sym"));
        assert!(matches!(&script.operations[4], RecordedOperation::CreateAuthKey { spec, .. }
        if spec.id == 0x0005));
        assert!(matches!(&script.operations[5], RecordedOperation::ExportWrapped { .. }));
        assert!(matches!(&script.operations[6], RecordedOperation::ImportWrapped { wrap_spec, wrapped_filepath, .. }
        if wrap_spec.wrapkey_id == 0x0010 && wrapped_filepath == "/tmp/wrapped.yhw"));

        assert!(matches!(&script.operations[7], RecordedOperation::BackupDevice { objects, destination_directory, .. }
        if objects[0].object_id == 0x0001 && destination_directory == "/backup"));

        assert!(matches!(&script.operations[8], RecordedOperation::RestoreDevice { source_directory, .. }
        if source_directory == "/restore"));
    }

// ════════════════════════════════════════════════════════════════
//  2. WrapOpSpec fields preserved through pipeline
// ════════════════════════════════════════════════════════════════

    #[test]
    fn test_wrap_op_spec_fields_preserved() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wrap_spec.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=WRAP0001".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::None,
            Box::new(JsonBackend),
        );
        let wrap_spec = WrapOpSpec {
            wrapkey_id: 0x00AA,
            wrapkey_type: WrapKeyType::RsaPublic,
            wrap_type: WrapType::Key,
            include_ed_seed: true,
            aes_algorithm: Some(ObjectAlgorithm::Aes128CcmWrap),
            oaep_algorithm: Some(ObjectAlgorithm::RsaOaepSha256),
            mgf1_algorithm: Some(ObjectAlgorithm::Mgf1Sha256),
        };
        rec.record(RecordedOperation::ExportWrapped {
            wrap_spec: wrap_spec.clone(),
            objects: vec![ObjectHandle { object_id: 1, object_type: ObjectType::AsymmetricKey }],
            destination_directory: "/export".to_string(),
        }).unwrap();

        let script = ScriptRunner::load(&path).unwrap();
        if let RecordedOperation::ExportWrapped { wrap_spec: loaded, .. } = &script.operations[0] {
            assert_eq!(loaded.wrapkey_id, 0x00AA);
            assert_eq!(loaded.wrapkey_type, WrapKeyType::RsaPublic);
            assert_eq!(loaded.wrap_type, WrapType::Key);
            assert!(loaded.include_ed_seed);
            assert_eq!(loaded.aes_algorithm, Some(ObjectAlgorithm::Aes128CcmWrap));
            assert_eq!(loaded.oaep_algorithm, Some(ObjectAlgorithm::RsaOaepSha256));
            assert_eq!(loaded.mgf1_algorithm, Some(ObjectAlgorithm::Mgf1Sha256));
        } else {
            panic!("Expected ExportWrapped");
        }
    }

// ════════════════════════════════════════════════════════════════
//  3. Error cases: corrupted/tampered script files
// ════════════════════════════════════════════════════════════════

    fn make_base_spec(id: u16, ot: ObjectType, algo: ObjectAlgorithm) -> RecordableObjectSpec {
        RecordableObjectSpec {
            id,
            object_type: ot,
            label: format!("test-{:04x}", id),
            algorithm: algo,
            domains: vec![ObjectDomain::One],
            capabilities: vec![ObjectCapability::SignPkcs],
            delegated_capabilities: vec![],
        }
    }

    #[test]
    fn test_load_truncated_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("truncated.json");
        // Write valid script, then truncate it
        let rec = SessionRecorder::new(
            "yhusb://serial=TRUNC001".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::Sensitive,
            Box::new(JsonBackend),
        );
        rec.record(RecordedOperation::GenerateObject {
            spec: make_base_spec(1, ObjectType::AsymmetricKey, ObjectAlgorithm::Rsa2048),
            context: "asym".to_string(),
        }).unwrap();

        // Truncate file
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &content[..content.len() / 2]).unwrap();

        assert!(ScriptRunner::load(&path).is_err());
    }

    #[test]
    fn test_load_tampered_version() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("tampered.json");
        let rec = SessionRecorder::new(
            "yhusb://serial=TAMPER01".to_string(),
            1,
            path.to_str().unwrap().to_string(),
            RedactMode::Sensitive,
            Box::new(JsonBackend),
        );
        rec.record(RecordedOperation::GenerateObject {
            spec: make_base_spec(1, ObjectType::AsymmetricKey, ObjectAlgorithm::Rsa2048),
            context: "asym".to_string(),
        }).unwrap();

        // Tamper: change version from "1.0" to "9.9"
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("\"1.0\"", "\"9.9\"");
        std::fs::write(&path, tampered).unwrap();

        let err = ScriptRunner::load(&path).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Unsupported script version"), "Got: {}", msg);
    }

    #[test]
    fn test_load_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        assert!(ScriptRunner::load(&path).is_err());
    }
}