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

#[derive(Debug, Clone, Copy, PartialEq,  Eq)]
pub enum MgmAlgorithm {
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EcK256,
    EcP224,
    EcP256,
    EcP384,
    EcP521,
    EcBp256,
    EcBp384,
    EcBp512,
    Ed25519,
    EcdsaSha1,
    EcdsaSha256,
    EcdsaSha384,
    EcdsaSha512,
// -------------- Signing Algorithms ----------
    RsaPkcs1Sha1,
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    RsaPssSha1,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
// -------------- Decryption Algorithms ----------
    RsaPkcs1Decrypt,
    RsaOaepSha1,
    RsaOaepSha256,
    RsaOaepSha384,
    RsaOaepSha512,
// --------------- Key Agreement Algorithms ----------
    Ecdh,
// --------------- Symmetric Key Algorithms ----------
    Aes128,
    Aes192,
    Aes256,
    AesEcb,
    AesCbc,
// --------------- Wrap Key Algorithms ----------
    Aes128CcmWrap,
    Aes192CcmWrap,
    Aes256CcmWrap,
// --------------- MGF1 Algorithms ----------
    Mgf1Sha1,
    Mgf1Sha256,
    Mgf1Sha384,
    Mgf1Sha512,
}

impl MgmAlgorithm {
    pub const fn algorithm(&self) -> ObjectAlgorithm {
        match self {
            MgmAlgorithm::Rsa2048 => ObjectAlgorithm::Rsa2048,
            MgmAlgorithm::Rsa3072 => ObjectAlgorithm::Rsa3072,
            MgmAlgorithm::Rsa4096 => ObjectAlgorithm::Rsa4096,
            MgmAlgorithm::EcK256 => ObjectAlgorithm::EcK256,
            MgmAlgorithm::EcP224 => ObjectAlgorithm::EcP224,
            MgmAlgorithm::EcP256 => ObjectAlgorithm::EcP256,
            MgmAlgorithm::EcP384 => ObjectAlgorithm::EcP384,
            MgmAlgorithm::EcP521 => ObjectAlgorithm::EcP521,
            MgmAlgorithm::EcBp256 => ObjectAlgorithm::EcBp256,
            MgmAlgorithm::EcBp384 => ObjectAlgorithm::EcBp384,
            MgmAlgorithm::EcBp512 => ObjectAlgorithm::EcBp512,
            MgmAlgorithm::Ed25519 => ObjectAlgorithm::Ed25519,
            MgmAlgorithm::EcdsaSha1 => ObjectAlgorithm::EcdsaSha1,
            MgmAlgorithm::EcdsaSha256 => ObjectAlgorithm::EcdsaSha256,
            MgmAlgorithm::EcdsaSha384 => ObjectAlgorithm::EcdsaSha384,
            MgmAlgorithm::EcdsaSha512 => ObjectAlgorithm::EcdsaSha512,
            MgmAlgorithm::RsaPkcs1Sha1 => ObjectAlgorithm::RsaPkcs1Sha1,
            MgmAlgorithm::RsaPkcs1Sha256 => ObjectAlgorithm::RsaPkcs1Sha256,
            MgmAlgorithm::RsaPkcs1Sha384 => ObjectAlgorithm::RsaPkcs1Sha384,
            MgmAlgorithm::RsaPkcs1Sha512 => ObjectAlgorithm::RsaPkcs1Sha512,
            MgmAlgorithm::RsaPssSha1 => ObjectAlgorithm::RsaPssSha1,
            MgmAlgorithm::RsaPssSha256 => ObjectAlgorithm::RsaPssSha256,
            MgmAlgorithm::RsaPssSha384 => ObjectAlgorithm::RsaPssSha384,
            MgmAlgorithm::RsaPssSha512 => ObjectAlgorithm::RsaPssSha512,
            MgmAlgorithm::RsaPkcs1Decrypt => ObjectAlgorithm::RsaPkcs1Decrypt,
            MgmAlgorithm::RsaOaepSha1 => ObjectAlgorithm::RsaOaepSha1,
            MgmAlgorithm::RsaOaepSha256 => ObjectAlgorithm::RsaOaepSha256,
            MgmAlgorithm::RsaOaepSha384 => ObjectAlgorithm::RsaOaepSha384,
            MgmAlgorithm::RsaOaepSha512 => ObjectAlgorithm::RsaOaepSha512,
            MgmAlgorithm::Ecdh => ObjectAlgorithm::Ecdh,
            MgmAlgorithm::Aes128 => ObjectAlgorithm::Aes128,
            MgmAlgorithm::Aes192 => ObjectAlgorithm::Aes192,
            MgmAlgorithm::Aes256 => ObjectAlgorithm::Aes256,
            MgmAlgorithm::AesEcb => ObjectAlgorithm::AesEcb,
            MgmAlgorithm::AesCbc => ObjectAlgorithm::AesCbc,
            MgmAlgorithm::Aes128CcmWrap => ObjectAlgorithm::Aes128CcmWrap,
            MgmAlgorithm::Aes192CcmWrap => ObjectAlgorithm::Aes192CcmWrap,
            MgmAlgorithm::Aes256CcmWrap => ObjectAlgorithm::Aes256CcmWrap,
            MgmAlgorithm::Mgf1Sha1 => ObjectAlgorithm::Mgf1Sha1,
            MgmAlgorithm::Mgf1Sha256 => ObjectAlgorithm::Mgf1Sha256,
            MgmAlgorithm::Mgf1Sha384 => ObjectAlgorithm::Mgf1Sha384,
            MgmAlgorithm::Mgf1Sha512 => ObjectAlgorithm::Mgf1Sha512,
        }
    }

    pub const fn label(&self) ->  &'static str {
        match self {
            MgmAlgorithm::Rsa2048 => "RSA 2048",
            MgmAlgorithm::Rsa3072 => "RSA 3072",
            MgmAlgorithm::Rsa4096 => "RSA 4096",
            MgmAlgorithm::EcK256 => "EC K-256",
            MgmAlgorithm::EcP224 => "EC SEC-P224",
            MgmAlgorithm::EcP256 => "EC SEC-P256",
            MgmAlgorithm::EcP384 => "EC SEC-P384",
            MgmAlgorithm::EcP521 => "EC SEC-P521",
            MgmAlgorithm::EcBp256 => "EC Brainpool P256",
            MgmAlgorithm::EcBp384 => "EC Brainpool P384",
            MgmAlgorithm::EcBp512 => "EC Brainpool P512",
            MgmAlgorithm::Ed25519 => "ED 25519",
            MgmAlgorithm::EcdsaSha1 => "ECDSA with SHA1",
            MgmAlgorithm::EcdsaSha256 => "ECDSA with SHA256",
            MgmAlgorithm::EcdsaSha384 => "ECDSA with SHA384",
            MgmAlgorithm::EcdsaSha512 => "ECDSA with SHA512",
            MgmAlgorithm::RsaPkcs1Sha1 => "RSA-PKCS#1v1.5 with SHA1",
            MgmAlgorithm::RsaPkcs1Sha256 => "RSA-PKCS#1v1.5 with SHA256",
            MgmAlgorithm::RsaPkcs1Sha384 => "RSA-PKCS#1v1.5 with SHA384",
            MgmAlgorithm::RsaPkcs1Sha512 => "RSA-PKCS#1v1.5 with SHA512",
            MgmAlgorithm::RsaPssSha1 => "RSA-PSS with SHA1",
            MgmAlgorithm::RsaPssSha256 => "RSA-PSS with SHA256",
            MgmAlgorithm::RsaPssSha384 => "RSA-PSS with SHA384",
            MgmAlgorithm::RsaPssSha512 => "RSA-PSS with SHA512",
            MgmAlgorithm::RsaPkcs1Decrypt => "RSA-PKCS#1v1.5",
            MgmAlgorithm::RsaOaepSha1 => "RSA-OAEP with SHA1",
            MgmAlgorithm::RsaOaepSha256 => "RSA-OAEP with SHA256",
            MgmAlgorithm::RsaOaepSha384 => "RSA-OAEP with SHA384",
            MgmAlgorithm::RsaOaepSha512 => "RSA-OAEP with SHA512",
            MgmAlgorithm::Ecdh => "ECDH",
            MgmAlgorithm::Aes128 => "AES128",
            MgmAlgorithm::Aes192 => "AES192",
            MgmAlgorithm::Aes256 => "AES256",
            MgmAlgorithm::AesEcb => "AES ECB",
            MgmAlgorithm::AesCbc => "AES CBC",
            MgmAlgorithm::Aes128CcmWrap => "AES128 CCM wrap",
            MgmAlgorithm::Aes192CcmWrap => "AES192 CCM wrap",
            MgmAlgorithm::Aes256CcmWrap => "AES256 CCM wrap",
            MgmAlgorithm::Mgf1Sha1 => "MGF1 with SHA1",
            MgmAlgorithm::Mgf1Sha256 => "MGF1 with SHA256",
            MgmAlgorithm::Mgf1Sha384 => "MGF1 with SHA384",
            MgmAlgorithm::Mgf1Sha512 => "MGF1 with SHA512",
        }
    }

    pub const fn description(&self) ->  &'static str {
        match self {
            MgmAlgorithm::Rsa2048 => "yubihsm-shell name: rsa2048",
            MgmAlgorithm::Rsa3072 => "yubihsm-shell name: rsa203072",
            MgmAlgorithm::Rsa4096 => "yubihsm-shell name: rsa4096",
            MgmAlgorithm::EcK256 => "curve: secp256k1. yubihsm-shell name: eck256",
            MgmAlgorithm::EcP224 => "curve: secp224r1. yubihsm-shell name: ecp224",
            MgmAlgorithm::EcP256 => "curve: secp256r1. yubihsm-shell name: ecp256",
            MgmAlgorithm::EcP384 => "curve: secp384r1. yubihsm-shell name: ecp384",
            MgmAlgorithm::EcP521 => "curve: secp521r1. yubihsm-shell name: ecp521",
            MgmAlgorithm::EcBp256 => "curve: brainpool256r1. yubihsm-shell name: ecbp256",
            MgmAlgorithm::EcBp384 => "curve: brainpool384r1. yubihsm-shell name: ecbp384",
            MgmAlgorithm::EcBp512 => "curve: brainpool512r1. yubihsm-shell name: ecbp512",
            MgmAlgorithm::Ed25519 => "yubihsm-shell name: ed25519",
            MgmAlgorithm::EcdsaSha1 => "yubihsm-shell name: ecdsa-sha1",
            MgmAlgorithm::EcdsaSha256 => "yubihsm-shell name: ecdsa-sha256",
            MgmAlgorithm::EcdsaSha384 => "yubihsm-shell name: ecdsa-sha384",
            MgmAlgorithm::EcdsaSha512 => "yubihsm-shell name: ecdsa-sha512",
            MgmAlgorithm::RsaPkcs1Sha1 => "yubihsm-shell name: rsa-pkcs1-sha1",
            MgmAlgorithm::RsaPkcs1Sha256 => "yubihsm-shell name: rsa-pkcs1-sha256",
            MgmAlgorithm::RsaPkcs1Sha384 => "yubihsm-shell name: rsa-pkcs1-sha384",
            MgmAlgorithm::RsaPkcs1Sha512 => "yubihsm-shell name: rsa-pkcs1-sha512",
            MgmAlgorithm::RsaPssSha1 => "yubihsm-shell name: rsa-pss-sha1",
            MgmAlgorithm::RsaPssSha256 => "yubihsm-shell name: rsa-pss-sha256",
            MgmAlgorithm::RsaPssSha384 => "yubihsm-shell name: rsa-pss-sha384",
            MgmAlgorithm::RsaPssSha512 => "yubihsm-shell name: rsa-pss-sha512",
            MgmAlgorithm::RsaPkcs1Decrypt => "yubihsm-shell name: rsa-pkcs1-decrypt",
            MgmAlgorithm::RsaOaepSha1 => "yubihsm-shell name: rsa-oaep-sha1",
            MgmAlgorithm::RsaOaepSha256 => "yubihsm-shell name: rsa-oaep-sha256",
            MgmAlgorithm::RsaOaepSha384 => "yubihsm-shell name: rsa-oaep-sha384",
            MgmAlgorithm::RsaOaepSha512 => "yubihsm-shell name: rsa-oaep-sha512",
            MgmAlgorithm::Ecdh => "yubihsm-shell name: ecdh",
            MgmAlgorithm::Aes128 => "yubihsm-shell name: aes128",
            MgmAlgorithm::Aes192 => "yubihsm-shell name: aes192",
            MgmAlgorithm::Aes256 => "yubihsm-shell name: aes256",
            MgmAlgorithm::AesEcb => "yubihsm-shell name: aes-ecb",
            MgmAlgorithm::AesCbc => "yubihsm-shell name: aes-cbc",
            MgmAlgorithm::Aes128CcmWrap => "yubihsm-shell name: aes128-ccm-wrap",
            MgmAlgorithm::Aes192CcmWrap => "yubihsm-shell name: aes192-ccm-wrap",
            MgmAlgorithm::Aes256CcmWrap => "yubihsm-shell name: aes256-ccm-wrap",
            MgmAlgorithm::Mgf1Sha1 => "yubihsm-shell name: mgf1-sha1",
            MgmAlgorithm::Mgf1Sha256 => "yubihsm-shell name: mgf1-sha256",
            MgmAlgorithm::Mgf1Sha384 => "yubihsm-shell name: mgf1-sha384",
            MgmAlgorithm::Mgf1Sha512 => "yubihsm-shell name: mgf1-sha512",
        }
    }

    pub const RSA_KEY_ALGORITHMS: [MgmAlgorithm; 3] = [
        MgmAlgorithm::Rsa2048,
        MgmAlgorithm::Rsa3072,
        MgmAlgorithm::Rsa4096,
    ];

    pub const EC_KEY_ALGORITHMS: [MgmAlgorithm; 8] = [
        MgmAlgorithm::EcK256,
        MgmAlgorithm::EcP224,
        MgmAlgorithm::EcP256,
        MgmAlgorithm::EcP384,
        MgmAlgorithm::EcP521,
        MgmAlgorithm::EcBp256,
        MgmAlgorithm::EcBp384,
        MgmAlgorithm::EcBp512,
    ];

    pub const ED_KEY_ALGORITHMS: [MgmAlgorithm; 1] = [
        MgmAlgorithm::Ed25519,
    ];

    pub const AES_KEY_ALGORITHMS: [MgmAlgorithm; 3] = [
        MgmAlgorithm::Aes128,
        MgmAlgorithm::Aes192,
        MgmAlgorithm::Aes256,
    ];

    pub const WRAP_KEY_ALGORITHMS: [MgmAlgorithm; 6] = [
        MgmAlgorithm::Aes128CcmWrap,
        MgmAlgorithm::Aes192CcmWrap,
        MgmAlgorithm::Aes256CcmWrap,
        MgmAlgorithm::Rsa2048,
        MgmAlgorithm::Rsa3072,
        MgmAlgorithm::Rsa4096,
    ];

    pub const RSA_PKCS_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm::RsaPkcs1Sha1,
        MgmAlgorithm::RsaPkcs1Sha256,
        MgmAlgorithm::RsaPkcs1Sha384,
        MgmAlgorithm::RsaPkcs1Sha512,
    ];

    pub const RSA_PSS_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm::RsaPssSha1,
        MgmAlgorithm::RsaPssSha256,
        MgmAlgorithm::RsaPssSha384,
        MgmAlgorithm::RsaPssSha512,
    ];

    pub const RSA_OAEP_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm::RsaOaepSha1,
        MgmAlgorithm::RsaOaepSha256,
        MgmAlgorithm::RsaOaepSha384,
        MgmAlgorithm::RsaOaepSha512,
    ];

    pub const ECDSA_ALGORITHMS: [MgmAlgorithm; 4] = [
        MgmAlgorithm::EcdsaSha1,
        MgmAlgorithm::EcdsaSha256,
        MgmAlgorithm::EcdsaSha384,
        MgmAlgorithm::EcdsaSha512,
    ];

    pub const EDDSA_ALGORITHMS: [MgmAlgorithm; 1] = [
        MgmAlgorithm::Ed25519,
    ];

    pub fn extract_algorithms(algorithms: &[MgmAlgorithm]) -> Vec<ObjectAlgorithm> {
        let mut algos = Vec::new();
        for a in algorithms {
            algos.push(a.algorithm());
        }
        algos
    }
}