use std::{error, fmt};

/// Enum listing possible errors from `YubiHSM`.
#[derive(Debug)]
pub enum MgmError {
    /// An error from an underlying libyubihsm call.
    LibYubiHsm(yubihsmrs::error::Error),
    /// An error from OpenSSL operations
    OpenSSLError(openssl::error::ErrorStack),
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
}

impl fmt::Display for MgmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MgmError::LibYubiHsm(err) => err.fmt(f),
            MgmError::OpenSSLError(err) => err.fmt(f),
            MgmError::StdIoError(err) => err.fmt(f),
            MgmError::PemError(err) => err.fmt(f),
            MgmError::HexError(err) => err.fmt(f),
            MgmError::InvalidInput(param) => write!(f, "Unsupported or unrecognized value: {}", param),
            MgmError::Error(param) => write!(f, "{}", param),
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
            MgmError::OpenSSLError(err) => Some(err),
            MgmError::StdIoError(err) => Some(err),
            MgmError::PemError(err) => Some(err),
            MgmError::HexError(err) => Some(err),
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