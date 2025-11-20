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

use yubihsmrs::object::ObjectAlgorithm;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MgmAlgorithm (ObjectAlgorithm);

impl From<ObjectAlgorithm> for MgmAlgorithm {
    fn from(alg: ObjectAlgorithm) -> Self {
        MgmAlgorithm(alg)
    }
}

impl MgmAlgorithm {

    pub const fn algorithm(&self) -> ObjectAlgorithm {
        self.0
    }

    pub const fn label(&self) ->  &'static str {
        match self.0 {
            ObjectAlgorithm::Rsa2048 => "RSA 2048",
            ObjectAlgorithm::Rsa3072 => "RSA 3072",
            ObjectAlgorithm::Rsa4096 => "RSA 4096",
            ObjectAlgorithm::EcK256 => "EC K-256",
            ObjectAlgorithm::EcP224 => "EC SEC-P224",
            ObjectAlgorithm::EcP256 => "EC SEC-P256",
            ObjectAlgorithm::EcP384 => "EC SEC-P384",
            ObjectAlgorithm::EcP521 => "EC SEC-P521",
            ObjectAlgorithm::EcBp256 => "EC Brainpool P256",
            ObjectAlgorithm::EcBp384 => "EC Brainpool P384",
            ObjectAlgorithm::EcBp512 => "EC Brainpool P512",
            ObjectAlgorithm::Ed25519 => "ED 25519",
            ObjectAlgorithm::EcdsaSha1 => "ECDSA with SHA1",
            ObjectAlgorithm::EcdsaSha256 => "ECDSA with SHA256",
            ObjectAlgorithm::EcdsaSha384 => "ECDSA with SHA384",
            ObjectAlgorithm::EcdsaSha512 => "ECDSA with SHA512",
            ObjectAlgorithm::RsaPkcs1Sha1 => "RSA-PKCS#1v1.5 with SHA1",
            ObjectAlgorithm::RsaPkcs1Sha256 => "RSA-PKCS#1v1.5 with SHA256",
            ObjectAlgorithm::RsaPkcs1Sha384 => "RSA-PKCS#1v1.5 with SHA384",
            ObjectAlgorithm::RsaPkcs1Sha512 => "RSA-PKCS#1v1.5 with SHA512",
            ObjectAlgorithm::RsaPssSha1 => "RSA-PSS with SHA1",
            ObjectAlgorithm::RsaPssSha256 => "RSA-PSS with SHA256",
            ObjectAlgorithm::RsaPssSha384 => "RSA-PSS with SHA384",
            ObjectAlgorithm::RsaPssSha512 => "RSA-PSS with SHA512",
            ObjectAlgorithm::RsaPkcs1Decrypt => "RSA-PKCS#1v1.5",
            ObjectAlgorithm::RsaOaepSha1 => "RSA-OAEP with SHA1",
            ObjectAlgorithm::RsaOaepSha256 => "RSA-OAEP with SHA256",
            ObjectAlgorithm::RsaOaepSha384 => "RSA-OAEP with SHA384",
            ObjectAlgorithm::RsaOaepSha512 => "RSA-OAEP with SHA512",
            ObjectAlgorithm::Ecdh => "ECDH",
            ObjectAlgorithm::Aes128 => "AES128",
            ObjectAlgorithm::Aes192 => "AES192",
            ObjectAlgorithm::Aes256 => "AES256",
            ObjectAlgorithm::AesEcb => "AES ECB",
            ObjectAlgorithm::AesCbc => "AES CBC",
            ObjectAlgorithm::Aes128CcmWrap => "AES128 CCM wrap",
            ObjectAlgorithm::Aes192CcmWrap => "AES192 CCM wrap",
            ObjectAlgorithm::Aes256CcmWrap => "AES256 CCM wrap",
            ObjectAlgorithm::Mgf1Sha1 => "MGF1 with SHA1",
            ObjectAlgorithm::Mgf1Sha256 => "MGF1 with SHA256",
            ObjectAlgorithm::Mgf1Sha384 => "MGF1 with SHA384",
            ObjectAlgorithm::Mgf1Sha512 => "MGF1 with SHA512",
            ObjectAlgorithm::Aes128YubicoAuthentication => "AES128 Yubico Authentication",
            ObjectAlgorithm::Ecp256YubicoAuthentication => "ECP256 Yubico Authentication",
            ObjectAlgorithm::OpaqueX509Certificate => "Opaque X509 Certificate",
            _ => "Unknown Algorithm"
        }
    }

    pub const fn description(&self) ->  &'static str {
        match self.0 {
            ObjectAlgorithm::Rsa2048 => "yubihsm-shell name: rsa2048",
            ObjectAlgorithm::Rsa3072 => "yubihsm-shell name: rsa203072",
            ObjectAlgorithm::Rsa4096 => "yubihsm-shell name: rsa4096",
            ObjectAlgorithm::EcK256 => "curve: secp256k1. yubihsm-shell name: eck256",
            ObjectAlgorithm::EcP224 => "curve: secp224r1. yubihsm-shell name: ecp224",
            ObjectAlgorithm::EcP256 => "curve: secp256r1. yubihsm-shell name: ecp256",
            ObjectAlgorithm::EcP384 => "curve: secp384r1. yubihsm-shell name: ecp384",
            ObjectAlgorithm::EcP521 => "curve: secp521r1. yubihsm-shell name: ecp521",
            ObjectAlgorithm::EcBp256 => "curve: brainpool256r1. yubihsm-shell name: ecbp256",
            ObjectAlgorithm::EcBp384 => "curve: brainpool384r1. yubihsm-shell name: ecbp384",
            ObjectAlgorithm::EcBp512 => "curve: brainpool512r1. yubihsm-shell name: ecbp512",
            ObjectAlgorithm::Ed25519 => "yubihsm-shell name: ed25519",
            ObjectAlgorithm::EcdsaSha1 => "yubihsm-shell name: ecdsa-sha1",
            ObjectAlgorithm::EcdsaSha256 => "yubihsm-shell name: ecdsa-sha256",
            ObjectAlgorithm::EcdsaSha384 => "yubihsm-shell name: ecdsa-sha384",
            ObjectAlgorithm::EcdsaSha512 => "yubihsm-shell name: ecdsa-sha512",
            ObjectAlgorithm::RsaPkcs1Sha1 => "yubihsm-shell name: rsa-pkcs1-sha1",
            ObjectAlgorithm::RsaPkcs1Sha256 => "yubihsm-shell name: rsa-pkcs1-sha256",
            ObjectAlgorithm::RsaPkcs1Sha384 => "yubihsm-shell name: rsa-pkcs1-sha384",
            ObjectAlgorithm::RsaPkcs1Sha512 => "yubihsm-shell name: rsa-pkcs1-sha512",
            ObjectAlgorithm::RsaPssSha1 => "yubihsm-shell name: rsa-pss-sha1",
            ObjectAlgorithm::RsaPssSha256 => "yubihsm-shell name: rsa-pss-sha256",
            ObjectAlgorithm::RsaPssSha384 => "yubihsm-shell name: rsa-pss-sha384",
            ObjectAlgorithm::RsaPssSha512 => "yubihsm-shell name: rsa-pss-sha512",
            ObjectAlgorithm::RsaPkcs1Decrypt => "yubihsm-shell name: rsa-pkcs1-decrypt",
            ObjectAlgorithm::RsaOaepSha1 => "yubihsm-shell name: rsa-oaep-sha1",
            ObjectAlgorithm::RsaOaepSha256 => "yubihsm-shell name: rsa-oaep-sha256",
            ObjectAlgorithm::RsaOaepSha384 => "yubihsm-shell name: rsa-oaep-sha384",
            ObjectAlgorithm::RsaOaepSha512 => "yubihsm-shell name: rsa-oaep-sha512",
            ObjectAlgorithm::Ecdh => "yubihsm-shell name: ecdh",
            ObjectAlgorithm::Aes128 => "yubihsm-shell name: aes128",
            ObjectAlgorithm::Aes192 => "yubihsm-shell name: aes192",
            ObjectAlgorithm::Aes256 => "yubihsm-shell name: aes256",
            ObjectAlgorithm::AesEcb => "yubihsm-shell name: aes-ecb",
            ObjectAlgorithm::AesCbc => "yubihsm-shell name: aes-cbc",
            ObjectAlgorithm::Aes128CcmWrap => "yubihsm-shell name: aes128-ccm-wrap",
            ObjectAlgorithm::Aes192CcmWrap => "yubihsm-shell name: aes192-ccm-wrap",
            ObjectAlgorithm::Aes256CcmWrap => "yubihsm-shell name: aes256-ccm-wrap",
            ObjectAlgorithm::Mgf1Sha1 => "yubihsm-shell name: mgf1-sha1",
            ObjectAlgorithm::Mgf1Sha256 => "yubihsm-shell name: mgf1-sha256",
            ObjectAlgorithm::Mgf1Sha384 => "yubihsm-shell name: mgf1-sha384",
            ObjectAlgorithm::Mgf1Sha512 => "yubihsm-shell name: mgf1-sha512",
            ObjectAlgorithm::Aes128YubicoAuthentication => "yubihsm-shell name: aes128-yubico-authentication",
            ObjectAlgorithm::Ecp256YubicoAuthentication => "yubihsm-shell name: ecp256-yubico-authentication",
            ObjectAlgorithm::OpaqueX509Certificate => "yubihsm-shell name: opaque-x509-certificate",
            _ => "Unknown Algorithm"
        }
    }

    pub const RSA_KEY_ALGORITHMS: [MgmAlgorithm; 3] = [
        MgmAlgorithm(ObjectAlgorithm::Rsa2048),
        MgmAlgorithm(ObjectAlgorithm::Rsa3072),
        MgmAlgorithm(ObjectAlgorithm::Rsa4096),
    ];

    pub const EC_KEY_ALGORITHMS: [MgmAlgorithm; 8] = [
        MgmAlgorithm(ObjectAlgorithm::EcK256),
        MgmAlgorithm(ObjectAlgorithm::EcP224),
        MgmAlgorithm(ObjectAlgorithm::EcP256),
        MgmAlgorithm(ObjectAlgorithm::EcP384),
        MgmAlgorithm(ObjectAlgorithm::EcP521),
        MgmAlgorithm(ObjectAlgorithm::EcBp256),
        MgmAlgorithm(ObjectAlgorithm::EcBp384),
        MgmAlgorithm(ObjectAlgorithm::EcBp512),
    ];

    pub const ED_KEY_ALGORITHMS: [MgmAlgorithm; 1] = [
        MgmAlgorithm(ObjectAlgorithm::Ed25519),
    ];

    pub const AES_KEY_ALGORITHMS: [MgmAlgorithm; 3] = [
        MgmAlgorithm(ObjectAlgorithm::Aes128),
        MgmAlgorithm(ObjectAlgorithm::Aes192),
        MgmAlgorithm(ObjectAlgorithm::Aes256),
    ];

    pub const WRAP_KEY_ALGORITHMS: [MgmAlgorithm; 6] = [
        MgmAlgorithm(ObjectAlgorithm::Aes128CcmWrap),
        MgmAlgorithm(ObjectAlgorithm::Aes192CcmWrap),
        MgmAlgorithm(ObjectAlgorithm::Aes256CcmWrap),
        MgmAlgorithm(ObjectAlgorithm::Rsa2048),
        MgmAlgorithm(ObjectAlgorithm::Rsa3072),
        MgmAlgorithm(ObjectAlgorithm::Rsa4096),
    ];

    pub const RSA_PKCS_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm(ObjectAlgorithm::RsaPkcs1Sha1),
        MgmAlgorithm(ObjectAlgorithm::RsaPkcs1Sha256),
        MgmAlgorithm(ObjectAlgorithm::RsaPkcs1Sha384),
        MgmAlgorithm(ObjectAlgorithm::RsaPkcs1Sha512),
    ];

    pub const RSA_PSS_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm(ObjectAlgorithm::RsaPssSha1),
        MgmAlgorithm(ObjectAlgorithm::RsaPssSha256),
        MgmAlgorithm(ObjectAlgorithm::RsaPssSha384),
        MgmAlgorithm(ObjectAlgorithm::RsaPssSha512),
    ];

    pub const RSA_OAEP_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm(ObjectAlgorithm::RsaOaepSha1),
        MgmAlgorithm(ObjectAlgorithm::RsaOaepSha256),
        MgmAlgorithm(ObjectAlgorithm::RsaOaepSha384),
        MgmAlgorithm(ObjectAlgorithm::RsaOaepSha512),
    ];

    pub const ECDSA_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm(ObjectAlgorithm::EcdsaSha1),
        MgmAlgorithm(ObjectAlgorithm::EcdsaSha256),
        MgmAlgorithm(ObjectAlgorithm::EcdsaSha384),
        MgmAlgorithm(ObjectAlgorithm::EcdsaSha512),
    ];

    pub const EDDSA_ALGORITHMS: [MgmAlgorithm; 1] = [
        MgmAlgorithm(ObjectAlgorithm::Ed25519),
    ];

    pub fn extract_algorithms(algorithms: &[MgmAlgorithm]) -> Vec<ObjectAlgorithm> {
        let mut algos = Vec::new();
        for a in algorithms {
            algos.push(a.algorithm());
        }
        algos
    }
}