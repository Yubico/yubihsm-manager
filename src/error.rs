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

use std::{error, fmt};

/// Enum listing possible errors from `YubiHSM`.
#[derive(Debug)]
pub enum MgmError {
    /// An error from an underlying libyubihsm call.
    LibYubiHsm(yubihsmrs::error::Error),
    /// An error from std::io
    StdIoError(std::io::Error),
    /// An error from pem::PemError
    PemError(pem::PemError),
    /// Hex parsing error
    HexError(hex::FromHexError),
    /// Unexpected or unsupported parameter
    InvalidInput(String),
    /// Generic Error
    Error(String),

    /// An error from public key parsing
    SpkiError(spki::Error),
    /// An error from public EC key parsing
    Sec1Error(sec1::Error),
    /// An error from PKCS8 parsing
    PKCS8Error(pkcs8::der::Error),
    /// An error from RSA public key parsing
    RsaError(rsa::Error),
    /// An error from RSA private key parsing
    RsaPkcs1Error(rsa::pkcs1::Error),
    /// An error from RSA public key parsing
    RsaSignatureError(rsa::signature::Error),
}

impl fmt::Display for MgmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MgmError::LibYubiHsm(err) => err.fmt(f),
            MgmError::StdIoError(err) => err.fmt(f),
            MgmError::PemError(err) => err.fmt(f),
            MgmError::HexError(err) => err.fmt(f),
            MgmError::InvalidInput(param) => write!(f, "Unsupported or unrecognized value: {}", param),
            MgmError::Error(param) => write!(f, "{}", param),

            MgmError::SpkiError(err) => err.fmt(f),
            MgmError::Sec1Error(err) => err.fmt(f),
            MgmError::PKCS8Error(err) => err.fmt(f),
            MgmError::RsaError(err) => err.fmt(f),
            MgmError::RsaPkcs1Error(err) => err.fmt(f),
            MgmError::RsaSignatureError(err) => err.fmt(f),
        }
    }
}

impl error::Error for MgmError {
    /*
    fn description(&self) -> &str {
        match *self {
            MgmError::LibYubiHsm(ref err) => err.description(),
            MgmError::OpenSSLError(ref err) => err.description(),
            MgmError::StdIoError(ref err) => err.description(),
            MgmError::HexError(ref err) => err.description(),
            MgmError::InvalidInput(_) => "Unexpected or unsupported parameter",
            MgmError::Error(_) => "Unspecified error clarified by an error message",
        }
    }
    */
    fn cause(&self) -> Option<&dyn error::Error> {
        match self {
            MgmError::LibYubiHsm(err) => Some(err),
            MgmError::StdIoError(err) => Some(err),
            MgmError::PemError(err) => Some(err),
            MgmError::HexError(err) => Some(err),
            MgmError::InvalidInput(_) => None,
            MgmError::Error(_) => None,

            MgmError::SpkiError(err) => Some(err),
            MgmError::Sec1Error(err) => Some(err),
            MgmError::PKCS8Error(err) => Some(err),
            MgmError::RsaError(err) => Some(err),
            MgmError::RsaPkcs1Error(err) => Some(err),
            MgmError::RsaSignatureError(err) => Some(err),
        }
    }
}

impl From<yubihsmrs::error::Error> for MgmError {
    fn from(error: yubihsmrs::error::Error) -> Self {
        MgmError::LibYubiHsm(error)
    }
}

// impl From<openssl::error::ErrorStack> for MgmError {
//     fn from(error: openssl::error::ErrorStack) -> Self {
//         MgmError::OpenSSLError(error)
//     }
// }

impl From<spki::Error> for MgmError {
    fn from(error: spki::Error) -> Self {
        MgmError::SpkiError(error)
    }
}

impl From<sec1::Error> for MgmError {
    fn from(error: sec1::Error) -> Self {
        MgmError::Sec1Error(error)
    }
}

impl From<pkcs8::der::Error> for MgmError {
    fn from(error: pkcs8::der::Error) -> Self {
        MgmError::PKCS8Error(error)
    }
}

impl From<rsa::Error> for MgmError {
    fn from(error: rsa::Error) -> Self {
        MgmError::RsaError(error)
    }
}

impl From<rsa::pkcs1::Error> for MgmError {
    fn from(error: rsa::pkcs1::Error) -> Self {
        MgmError::RsaPkcs1Error(error)
    }
}

impl From<rsa::signature::Error> for MgmError {
    fn from(error: rsa::signature::Error) -> Self {
        MgmError::RsaSignatureError(error)
    }
}

impl From<std::io::Error> for MgmError {
    fn from(error: std::io::Error) -> Self {
        MgmError::StdIoError(error)
    }
}

impl From<pem::PemError> for MgmError {
    fn from(error: pem::PemError) -> Self {
        MgmError::PemError(error)
    }
}

impl From<hex::FromHexError> for MgmError {
    fn from(error: hex::FromHexError) -> Self {
        MgmError::HexError(error)
    }
}