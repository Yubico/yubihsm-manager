use std::{error, fmt};
use std::error::Error;
use std::fmt::write;

/// Enum listing possible errors from `YubiHSM`.
#[derive(Debug, Clone)]
pub enum MgmError {
    /// An error from an underlying libyubihsm call.
    LibYubiHsm(yubihsmrs::error::Error),
    /// An error from OpenSSL operations
    OpenSSLError(openssl::error::ErrorStack),
    /// Unexpected or unsupported parameter
    InvalidInput(String),
    /// Generic Error
    Error(String),
}

impl fmt::Display for MgmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MgmError::LibYubiHsm(ref err) => err.fmt(f),
            MgmError::OpenSSLError(ref err) => err.fmt(f),
            MgmError::InvalidInput(ref param) => write!(f, "Unsupported or unrecognized value: {}", param),
            MgmError::Error(ref param) => write!(f, "{}", param),
        }
    }
}

impl error::Error for MgmError {
    fn description(&self) -> &str {
        match *self {
            MgmError::LibYubiHsm(ref err) => err.description(),
            MgmError::OpenSSLError(ref err) => err.description(),
            MgmError::InvalidInput(_) => "Unexpected or unsupported parameter",
            MgmError::Error(_) => "Unspecified error clarified by an error message",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            MgmError::LibYubiHsm(ref err) => Some(err),
            MgmError::OpenSSLError(ref err) => Some(err),
            MgmError::InvalidInput(_) => None,
            MgmError::Error(_) => None,
        }
    }
}

impl From<yubihsmrs::error::Error> for MgmError {
    fn from(error: yubihsmrs::error::Error) -> Self {
        MgmError::LibYubiHsm(error)
    }
}

impl From<openssl::error::ErrorStack> for MgmError {
    fn from(error: openssl::error::ErrorStack) -> Self {
        MgmError::OpenSSLError(error)
    }
}