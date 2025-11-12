use yubihsmrs::object::ObjectAlgorithm;
use crate::backend::types::YhAlgorithm;

impl YhAlgorithm {
    // ---------- Key Algorithms ----------
    pub const RSA2048: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Rsa2048,
        label: "RSA 2048",
        description: "yubihsm-shell name: rsa2048",
    };

    pub const RSA3072: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Rsa3072,
        label: "RSA 3072",
        description: "yubihsm-shell name: rsa203072",
    };

    pub const RSA4096: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Rsa4096,
        label: "RSA 4096",
        description: "yubihsm-shell name: rsa4096",
    };

    pub const EC_K256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcK256,
        label: "EC K-256",
        description: "curve: secp256k1. yubihsm-shell name: eck256",
    };

    pub const EC_P224: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcP224,
        label: "EC SEC-P224",
        description: "curve: secp224r1. yubihsm-shell name: ecp224",
    };

    pub const EC_P256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcP256,
        label: "EC SEC-P256",
        description: "curve: secp256r1. yubihsm-shell name: ecp256",
    };

    pub const EC_P384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcP384,
        label: "EC SEC-P384",
        description: "curve: secp384r1. yubihsm-shell name: ecp384",
    };

    pub const EC_P521: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcP521,
        label: "EC SEC-P521",
        description: "curve: secp521r1. yubihsm-shell name: ecp521",
    };

    pub const ECBP_P256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcBp256,
        label: "EC Brainpool P256",
        description: "curve: brainpool256r1. yubihsm-shell name: ecbp256",
    };

    pub const ECBP_P384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcBp384,
        label: "EC Brainpool P384",
        description: "curve: brainpool384r1. yubihsm-shell name: ecbp384",
    };

    pub const ECBP_P512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcBp512,
        label: "EC Brainpool P512",
        description: "curve: brainpool512r1. yubihsm-shell name: ecbp512",
    };

    pub const ED25519: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Ed25519,
        label: "ED 25519",
        description: "yubihsm-shell name: ed25519",
    };


// ---------------- Signature Algorithms ----------

    pub const ECDSA_SHA1: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcdsaSha1,
        label: "ECDSA with SHA1",
        description: "yubihsm-shell name: ecdsa-sha1",
    };

    pub const ECDSA_SHA256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcdsaSha256,
        label: "ECDSA with SHA256",
        description: "yubihsm-shell name: ecdsa-sha256",
    };

    pub const ECDSA_SHA384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcdsaSha384,
        label: "ECDSA with SHA384",
        description: "yubihsm-shell name: ecdsa-sha384",
    };

    pub const ECDSA_SHA512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::EcdsaSha512,
        label: "ECDSA with SHA512",
        description: "yubihsm-shell name: ecdsa-sha512",
    };

    pub const RSA_PKCS1_SHA1: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPkcs1Sha1,
        label: "RSA-PKCS#1v1.5 with SHA1",
        description: "yubihsm-shell name: rsa-pkcs1-sha1",
    };

    pub const RSA_PKCS1_SHA256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPkcs1Sha256,
        label: "RSA-PKCS#1v1.5 with SHA256",
        description: "yubihsm-shell name: rsa-pkcs1-sha256",
    };

    pub const RSA_PKCS1_SHA384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPkcs1Sha384,
        label: "RSA-PKCS#1v1.5 with SHA384",
        description: "yubihsm-shell name: rsa-pkcs1-sha384",
    };

    pub const RSA_PKCS1_SHA512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPkcs1Sha512,
        label: "RSA-PKCS#1v1.5 with SHA512",
        description: "yubihsm-shell name: rsa-pkcs1-sha512",
    };

    pub const RSA_PSS_SHA1: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPssSha1,
        label: "RSA-PSS with SHA1",
        description: "yubihsm-shell name: rsa-pss-sha1",
    };

    pub const RSA_PSS_SHA256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPssSha256,
        label: "RSA-PSS with SHA256",
        description: "yubihsm-shell name: rsa-pss-sha256",
    };

    pub const RSA_PSS_SHA384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPssSha384,
        label: "RSA-PSS with SHA384",
        description: "yubihsm-shell name: rsa-pss-sha384",
    };

    pub const RSA_PSS_SHA512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPssSha512,
        label: "RSA-PSS with SHA512",
        description: "yubihsm-shell name: rsa-pss-sha512",
    };

// -------------- Decryption Algorithms ----------

    pub const RSA_PKCS1_DECRYPT: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaPkcs1Decrypt,
        label: "RSA-PKCS#1v1.5",
        description: "yubihsm-shell name: rsa-pkcs1-decrypt",
    };

    pub const RSA_OAEP_SHA1: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaOaepSha1,
        label: "RSA-OAEP with SHA1",
        description: "yubihsm-shell name: rsa-oaep-sha1",
    };

    pub const RSA_OAEP_SHA256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaOaepSha256,
        label: "RSA-OAEP with SHA256",
        description: "yubihsm-shell name: rsa-oaep-sha256",
    };

    pub const RSA_OAEP_SHA384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaOaepSha384,
        label: "RSA-OAEP with SHA384",
        description: "yubihsm-shell name: rsa-oaep-sha384",
    };

    pub const RSA_OAEP_SHA512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::RsaOaepSha512,
        label: "RSA-OAEP with SHA512",
        description: "yubihsm-shell name: rsa-oaep-sha512",
    };

// --------------- Key Agreement Algorithms ----------

    pub const ECDH: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Ecdh,
        label: "ECDH",
        description: "yubihsm-shell name: ecdh",
    };

// --------------- Symmetric Key Algorithms ----------

    pub const AES128: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes128,
        label: "AES128",
        description: "yubihsm-shell name: aes128",
    };

    pub const AES192: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes192,
        label: "AES192",
        description: "yubihsm-shell name: aes192",
    };

    pub const AES256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes256,
        label: "AES256",
        description: "yubihsm-shell name: aes256",
    };

    pub const AES_ECB: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::AesEcb,
        label: "AES ECB",
        description: "yubihsm-shell name: aes-ecb",
    };

    pub const AES_CBC: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::AesCbc,
        label: "AES CBC",
        description: "yubihsm-shell name: aes-cbc",
    };

// --------------- Wrap Key Algorithms ----------

    pub const AES128_CCM_WRAP: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes128CcmWrap,
        label: "AES128 CCM wrap",
        description: "yubihsm-shell name: aes128-ccm-wrap",
    };

    pub const AES192_CCM_WRAP: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes192CcmWrap,
        label: "AES192 CCM wrap",
        description: "yubihsm-shell name: aes192-ccm-wrap",
    };

    pub const AES256_CCM_WRAP: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Aes256CcmWrap,
        label: "AES256 CCM wrap",
        description: "yubihsm-shell name: aes256-ccm-wrap",
    };

// --------------- MGF1 Algorithms ----------

    pub const MGF1_SHA1: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Mgf1Sha1,
        label: "MGF1 with SHA1",
        description: "yubihsm-shell name: mgf1-sha1",
    };

    pub const MGF1_SHA256: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Mgf1Sha256,
        label: "MGF1 with SHA256",
        description: "yubihsm-shell name: mgf1-sha256",
    };

    pub const MGF1_SHA384: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Mgf1Sha384,
        label: "MGF1 with SHA384",
        description: "yubihsm-shell name: mgf1-sha384",
    };

    pub const MGF1_SHA512: YhAlgorithm = YhAlgorithm {
        algorithm: ObjectAlgorithm::Mgf1Sha512,
        label: "MGF1 with SHA512",
        description: "yubihsm-shell name: mgf1-sha512",
    };
}