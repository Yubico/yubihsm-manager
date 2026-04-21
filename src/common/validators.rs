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

use std::sync::LazyLock;
use regex::Regex;
use pem::Pem;
use yubihsmrs::object::{ObjectAlgorithm, ObjectType};
use crate::common::error::MgmError;
use crate::hsm_operations::asym::AsymmetricOperations;

static SHARE_RE_256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-fA-F0-9]{104}$").unwrap());
static SHARE_RE_192: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-fA-F0-9]{88}$").unwrap());
static SHARE_RE_128: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d-\d-[a-fA-F0-9]{72}$").unwrap());

pub fn object_id_validator(input: &str) -> Result<(), MgmError> {
    let id = if let Some(hex) = input.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        input.parse()
    };
    match id {
        Ok(id) if (0..=0xffff).contains(&id) => Ok(()),
        _ => Err(MgmError::InvalidInput("ID must be a number in [0, 65535]".to_string())),
    }
}

pub fn object_label_validator(input: &str) -> Result<(), MgmError> {
    if input.len() > 40 {
        Err(MgmError::InvalidInput("Label must be at most 40 characters long".to_string()))
    } else {
        Ok(())
    }
}

pub fn path_exists_validator(input: &str) -> Result<(), MgmError> {
    if std::path::Path::new(input).exists() {
        Ok(())
    } else {
        Err(MgmError::InvalidInput("No such file or directory".to_string()))
    }
}

pub fn integer_validator(input: &str, min: usize, max: usize) -> Result<(), MgmError> {
    match input.parse::<usize>() {
        Ok(value) if (min..=max).contains(&value) => Ok(()),
        _ => Err(MgmError::InvalidInput(format!("Input must be an integer in [{}, {}]", min, max))),
    }
}

pub fn hex_validator(input: &str) -> Result<(), MgmError> {
    match hex::decode(input) {
        Ok(_) => Ok(()),
        _ => Err(MgmError::InvalidInput("Input not in HEX format".to_string())),
    }
}

pub fn aes_key_validator(input: &str) -> Result<(), MgmError> {
    let key_bytes = match hex::decode(input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(MgmError::InvalidInput("AES key not in HEX format".to_string())),
    };
    match key_bytes.len() {
        16 | 24 | 32 => Ok(()),
        _ => Err(MgmError::InvalidInput("AES key must be 16, 24, or 32 bytes long".to_string())),
    }
}

pub fn aes_key_of_length_validator(input: &str, keylen: usize) -> Result<(), MgmError> {
    let key_bytes = match hex::decode(input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(MgmError::InvalidInput("AES key not in HEX format".to_string())),
    };
    if key_bytes.len() != keylen {
        return Err(MgmError::InvalidInput(format!("Key must be {} bytes long", keylen)));
    }
    Ok(())
}

pub fn aes_operation_input_validator(input: &str) -> Result<(), MgmError> {
    let data_bytes = match hex::decode(input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(MgmError::InvalidInput("Input not in HEX format".to_string())),
    };
    match data_bytes.len() % 16 {
        0 => Ok(()),
        _ => Err(MgmError::InvalidInput("Input data must be a multiple of 16 bytes long".to_string())),
    }
}

pub fn iv_validator(input: &str) -> Result<(), MgmError> {
    let iv_bytes = match hex::decode(input) {
        Ok(bytes) => bytes,
        Err(_) => return Err(MgmError::InvalidInput("IV not in HEX format".to_string())),
    };
    match iv_bytes.len() {
        16 => Ok(()),
        _ => Err(MgmError::InvalidInput("IV must be 16 bytes long".to_string())),
    }
}

pub fn pem_file_validator(input: &str) -> Result<(), MgmError> {
    match get_validated_pem_content(input) {
        Ok(_) => Ok(()),
        Err(_) => Err(MgmError::InvalidInput("File is not a valid PEM".to_string())),
    }
}

pub fn pem_certificate_file_validator(input: &str, required: bool) -> Result<(), MgmError> {
    if input.is_empty() && !required {
        return Ok(());
    }
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _algo != ObjectAlgorithm::OpaqueX509Certificate {
        return Err(MgmError::InvalidInput("Found PEM object is not an X509Certificate".to_string()));
    }
    Ok(())
}

pub fn pem_asymmetric_object_file_validator(input: &str, object_type: ObjectType, object_algorithm: ObjectAlgorithm) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != object_type || _algo != object_algorithm {
        return Err(MgmError::InvalidInput("Found PEM object with unexpected type or algorithm".to_string()));
    }
    Ok(())
}

pub fn pem_private_key_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::AsymmetricKey {
        return Err(MgmError::InvalidInput("Found PEM object is not an asymmetric private key".to_string()));
    }
    Ok(())
}

pub fn pem_public_eckey_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || !AsymmetricOperations::is_ec_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("Found PEM object is not a public EC key".to_string()));
    }
    Ok(())
}

pub fn pem_public_ecp256_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || _algo != ObjectAlgorithm::EcP256 {
        return Err(MgmError::InvalidInput("Found PEM object is not a public ECP256 key".to_string()));
    }
    Ok(())
}

pub fn pem_private_ecp256_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::AsymmetricKey || _algo != ObjectAlgorithm::EcP256 {
        return Err(MgmError::InvalidInput("Found PEM object is not a private ECP256 key".to_string()));
    }
    Ok(())
}

pub fn pem_private_rsa_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::AsymmetricKey || !AsymmetricOperations::is_rsa_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("Found PEM object is not a private RSA key".to_string()));
    }
    Ok(())
}

pub fn pem_public_rsa_file_validator(input: &str) -> Result<(), MgmError> {
    let pem = get_validated_pem_content(input)?[0].to_owned();
    let (_type, _algo, _) = AsymmetricOperations::parse_asym_pem(pem)?;
    if _type != ObjectType::PublicKey || !AsymmetricOperations::is_rsa_key_algorithm(&_algo) {
        return Err(MgmError::InvalidInput("Found PEM object is not a public RSA key".to_string()));
    }
    Ok(())
}
pub fn pem_sunpkcs11_file_validator(input: &str) -> Result<(), MgmError> {
    let pems = get_validated_pem_content(input)?;
    let mut privkey_found = false;
    let mut cert_found = false;
    for pem in pems {
        let (_type, _algo, _bytes) = AsymmetricOperations::parse_asym_pem(pem.clone())?;
        if _type == ObjectType::AsymmetricKey {
            privkey_found = true;
        } else if _algo == ObjectAlgorithm::OpaqueX509Certificate {
            cert_found = true;
        }
        if privkey_found && cert_found {
            return Ok(())
        }
    }
    Err(MgmError::InvalidInput("PEM file must contain both a private key and an X509Certificate".to_string()))
}

pub fn aes_share_validator(input: &str, share_length: Option<u8>) -> Result<(), MgmError> {
    let is_valid = match share_length {
        Some(108) => SHARE_RE_256.is_match(input),  // 4 prefix chars + 104 hex
        Some(92)  => SHARE_RE_192.is_match(input),  // 4 prefix chars + 88 hex
        Some(76)  => SHARE_RE_128.is_match(input),  // 4 prefix chars + 72 hex
        None => {
            SHARE_RE_256.is_match(input) ||
            SHARE_RE_192.is_match(input) ||
            SHARE_RE_128.is_match(input)
        },
        _ => false,
    };
    if is_valid {
        Ok(())
    } else {
        Err(MgmError::InvalidInput("Share format is invalid".to_string()))
    }
}

// Helper functions

fn get_validated_pem_content(input: &str) -> Result<Vec<Pem>, MgmError> {
    if !std::path::Path::new(input).exists() {
        return Err(MgmError::InvalidInput("File does not exist".to_string()));
    }
    let content = std::fs::read_to_string(input)?;
    match pem::parse_many(content) {
       Ok(pems) => {
           if pems.is_empty() {
               return Err(MgmError::InvalidInput("File does not contain valid PEM objects".to_string()));
           }
           Ok(pems)
       },
       Err(_) => Err(MgmError::InvalidInput("File is not a valid PEM".to_string())),
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ── object_id_validator ──

    #[test]
    fn test_object_id_zero() {
        assert!(object_id_validator("0").is_ok());
    }

    #[test]
    fn test_object_id_max() {
        assert!(object_id_validator("65535").is_ok());
    }

    #[test]
    fn test_object_id_hex_lower() {
        assert!(object_id_validator("0x0001").is_ok());
    }

    #[test]
    fn test_object_id_hex_max() {
        assert!(object_id_validator("0xffff").is_ok());
    }

    #[test]
    fn test_object_id_out_of_range() {
        // u16 max is 65535; "65536" won't parse as u16
        assert!(object_id_validator("65536").is_err());
    }

    #[test]
    fn test_object_id_non_numeric() {
        assert!(object_id_validator("abc").is_err());
    }

    #[test]
    fn test_object_id_empty() {
        assert!(object_id_validator("").is_err());
    }

    // ── object_label_validator ──

    #[test]
    fn test_label_max_length() {
        let label = "a".repeat(40);
        assert!(object_label_validator(&label).is_ok());
    }

    #[test]
    fn test_label_too_long() {
        let label = "a".repeat(41);
        assert!(object_label_validator(&label).is_err());
    }

    #[test]
    fn test_label_empty() {
        assert!(object_label_validator("").is_ok());
    }

    // ── integer_validator ──

    #[test]
    fn test_integer_in_range() {
        assert!(integer_validator("5", 1, 10).is_ok());
    }

    #[test]
    fn test_integer_at_min() {
        assert!(integer_validator("1", 1, 10).is_ok());
    }

    #[test]
    fn test_integer_at_max() {
        assert!(integer_validator("10", 1, 10).is_ok());
    }

    #[test]
    fn test_integer_below_min() {
        assert!(integer_validator("0", 1, 10).is_err());
    }

    #[test]
    fn test_integer_above_max() {
        assert!(integer_validator("11", 1, 10).is_err());
    }

    #[test]
    fn test_integer_not_a_number() {
        assert!(integer_validator("abc", 1, 10).is_err());
    }

    // ── hex_validator ──

    #[test]
    fn test_hex_valid() {
        assert!(hex_validator("deadbeef").is_ok());
    }

    #[test]
    fn test_hex_odd_length() {
        assert!(hex_validator("abc").is_err());
    }

    #[test]
    fn test_hex_non_hex_chars() {
        assert!(hex_validator("ghij").is_err());
    }

    // ── aes_key_validator ──

    #[test]
    fn test_aes_key_128() {
        let key = "00".repeat(16); // 16 bytes
        assert!(aes_key_validator(&key).is_ok());
    }

    #[test]
    fn test_aes_key_192() {
        let key = "00".repeat(24);
        assert!(aes_key_validator(&key).is_ok());
    }

    #[test]
    fn test_aes_key_256() {
        let key = "00".repeat(32);
        assert!(aes_key_validator(&key).is_ok());
    }

    #[test]
    fn test_aes_key_wrong_length() {
        let key = "00".repeat(15);
        assert!(aes_key_validator(&key).is_err());
    }

    #[test]
    fn test_aes_key_not_hex() {
        assert!(aes_key_validator("not_hex_at_all!!").is_err());
    }

    // ── aes_key_of_length_validator ──

    #[test]
    fn test_aes_key_of_length_correct() {
        let key = "00".repeat(16);
        assert!(aes_key_of_length_validator(&key, 16).is_ok());
    }

    #[test]
    fn test_aes_key_of_length_wrong() {
        let key = "00".repeat(16);
        assert!(aes_key_of_length_validator(&key, 24).is_err());
    }

    // ── aes_operation_input_validator ──

    #[test]
    fn test_aes_input_16_bytes() {
        let input = "00".repeat(16);
        assert!(aes_operation_input_validator(&input).is_ok());
    }

    #[test]
    fn test_aes_input_32_bytes() {
        let input = "00".repeat(32);
        assert!(aes_operation_input_validator(&input).is_ok());
    }

    #[test]
    fn test_aes_input_17_bytes() {
        let input = "00".repeat(17);
        assert!(aes_operation_input_validator(&input).is_err());
    }

    // ── iv_validator ──

    #[test]
    fn test_iv_valid() {
        let iv = "00".repeat(16);
        assert!(iv_validator(&iv).is_ok());
    }

    #[test]
    fn test_iv_wrong_length() {
        let iv = "00".repeat(15);
        assert!(iv_validator(&iv).is_err());
    }

    #[test]
    fn test_iv_not_hex() {
        assert!(iv_validator("not_hex_value!!!").is_err());
    }

    // ── aes_share_validator ──

    // Helper: build a fake share string of the right format
    fn make_share(hex_len: usize) -> String {
        // Format: "D-D-<hex_chars>" where D are single digits
        let hex_chars: String = "a".repeat(hex_len);
        format!("2-3-{}", hex_chars)
    }

    #[test]
    fn test_share_128_valid() {
        assert!(aes_share_validator(&make_share(72), Some(76)).is_ok());
    }

    #[test]
    fn test_share_192_valid() {
        assert!(aes_share_validator(&make_share(88), Some(92)).is_ok());
    }

    #[test]
    fn test_share_256_valid() {
        assert!(aes_share_validator(&make_share(104), Some(108)).is_ok());
    }

    #[test]
    fn test_share_invalid_format() {
        assert!(aes_share_validator("not-a-share", None).is_err());
    }

    #[test]
    fn test_share_wrong_length_hint() {
        // 256-bit share (104 hex chars) but expecting 128-bit (76)
        assert!(aes_share_validator(&make_share(104), Some(76)).is_err());
    }

    #[test]
    fn test_share_none_accepts_any_valid() {
        assert!(aes_share_validator(&make_share(72), None).is_ok());
        assert!(aes_share_validator(&make_share(88), None).is_ok());
        assert!(aes_share_validator(&make_share(104), None).is_ok());
    }

    // ── path_exists_validator ──

    #[test]
    fn test_path_exists() {
        let f = NamedTempFile::new().unwrap();
        assert!(path_exists_validator(f.path().to_str().unwrap()).is_ok());
    }

    #[test]
    fn test_path_not_exists() {
        assert!(path_exists_validator("/nonexistent/path/to/file.txt").is_err());
    }

    // ── PEM file validators ──
    // These require the test files to be present in test/fixture
    // If fixtures are not present, these tests will fail with a clear message.

    fn fixture_path(name: &str) -> String {
        let path = format!("resources/test_data/{}", name);
        assert!(
            std::path::Path::new(&path).exists(),
            "Test fixture missing: {}",
            path
        );
        path
    }

    #[test]
    fn test_pem_file_valid() {
        assert!(pem_file_validator(&fixture_path("rsa2048_private.pem")).is_ok());
    }

    #[test]
    fn test_pem_file_nonexistent() {
        assert!(pem_file_validator("/no/such/file.pem").is_err());
    }

    #[test]
    fn test_pem_file_not_pem() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "this is not a PEM file").unwrap();
        assert!(pem_file_validator(f.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn test_pem_private_key_validator_rsa() {
        assert!(pem_private_key_file_validator(&fixture_path("rsa2048_private.pem")).is_ok());
    }

    #[test]
    fn test_pem_private_key_validator_rejects_public() {
        assert!(pem_private_key_file_validator(&fixture_path("ecp256_public.pem")).is_err());
    }

    #[test]
    fn test_pem_certificate_validator_valid() {
        assert!(pem_certificate_file_validator(&fixture_path("x509_cert.pem"), true).is_ok());
    }

    #[test]
    fn test_pem_certificate_validator_rejects_privkey() {
        assert!(pem_certificate_file_validator(&fixture_path("rsa2048_private.pem"), true).is_err());
    }

    #[test]
    fn test_pem_certificate_validator_empty_not_required() {
        assert!(pem_certificate_file_validator("", false).is_ok());
    }

    #[test]
    fn test_pem_public_eckey_valid() {
        assert!(pem_public_eckey_file_validator(&fixture_path("ecp256_public.pem")).is_ok());
    }

    #[test]
    fn test_pem_public_eckey_rejects_rsa() {
        assert!(pem_public_eckey_file_validator(&fixture_path("rsa2048_public.pem")).is_err());
    }

    #[test]
    fn test_pem_public_ecp256_valid() {
        assert!(pem_public_ecp256_file_validator(&fixture_path("ecp256_public.pem")).is_ok());
    }

    #[test]
    fn test_pem_public_ecp256_rejects_p384() {
        assert!(pem_public_ecp256_file_validator(&fixture_path("ecp384_public.pem")).is_err());
    }

    #[test]
    fn test_pem_private_ecp256_valid() {
        assert!(pem_private_ecp256_file_validator(&fixture_path("ecp256_private.pem")).is_ok());
    }

    #[test]
    fn test_pem_private_ecp256_rejects_rsa() {
        assert!(pem_private_ecp256_file_validator(&fixture_path("rsa2048_private.pem")).is_err());
    }

    #[test]
    fn test_pem_private_rsa_valid() {
        assert!(pem_private_rsa_file_validator(&fixture_path("rsa2048_private.pem")).is_ok());
    }

    #[test]
    fn test_pem_private_rsa_rejects_ec() {
        assert!(pem_private_rsa_file_validator(&fixture_path("ecp256_private.pem")).is_err());
    }

    #[test]
    fn test_pem_public_rsa_valid() {
        assert!(pem_public_rsa_file_validator(&fixture_path("rsa2048_public.pem")).is_ok());
    }

    #[test]
    fn test_pem_public_rsa_rejects_ec() {
        assert!(pem_public_rsa_file_validator(&fixture_path("ecp256_public.pem")).is_err());
    }

    #[test]
    fn test_pem_sunpkcs11_valid() {
        assert!(pem_sunpkcs11_file_validator(&fixture_path("sunpkcs11_combo.pem")).is_ok());
    }

    #[test]
    fn test_pem_sunpkcs11_rejects_privkey_only() {
        assert!(pem_sunpkcs11_file_validator(&fixture_path("ecp256_private.pem")).is_err());
    }

    #[test]
    fn test_pem_asymmetric_object_validator_matching() {
        assert!(pem_asymmetric_object_file_validator(
            &fixture_path("ecp256_private.pem"),
            ObjectType::AsymmetricKey,
            ObjectAlgorithm::EcP256,
        ).is_ok());
    }

    #[test]
    fn test_pem_asymmetric_object_validator_mismatched_type() {
        assert!(pem_asymmetric_object_file_validator(
            &fixture_path("ecp256_private.pem"),
            ObjectType::PublicKey,  // wrong type
            ObjectAlgorithm::EcP256,
        ).is_err());
    }
}