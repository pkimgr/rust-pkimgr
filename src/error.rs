use core::fmt;
use std::io;

use openssl::error::ErrorStack;

// PKIError management
#[derive(Debug)]
pub enum PKIError {
    NotFound(String),
    OpenSSL(ErrorStack),
    JsonError(String)
}


impl std::error::Error for PKIError {}

impl From<ErrorStack> for PKIError {
    fn from(err: ErrorStack) -> PKIError {
        PKIError::OpenSSL(err)
    }
}

impl fmt::Display for PKIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PKIError::NotFound(err) => write!(f, "{}", err),
            PKIError::OpenSSL(err) => write!(f, "{}", err),
            PKIError::JsonError(err) => write!(f, "{}", err)
        }
    }
}

#[derive(Debug)]
pub enum ManagerError {
    NotFound(String),
    IOError(String),
    PKIError(PKIError),
    JsonError(String),
    OpenSSL(ErrorStack)
}

impl From<io::Error> for ManagerError {
    fn from(value: io::Error) -> Self {
        ManagerError::IOError(format!("{}", value.to_string()))
    }
}

impl From<ErrorStack> for ManagerError {
    fn from(value: ErrorStack) -> Self {
        ManagerError::OpenSSL(value)
    }
}

impl From<serde_json::Error> for ManagerError {
    fn from(value: serde_json::Error) -> Self {
        ManagerError::JsonError(value.to_string())
    }
}

impl From<PKIError> for ManagerError {
    fn from(value: PKIError) -> Self {
        ManagerError::PKIError(value)
    }
}

impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagerError::IOError(err) => write!(f, "IOError: {}", err),
            ManagerError::JsonError(err) => write!(f, "JSONError: {}", err),
            ManagerError::NotFound(err) => write!(f, "NotfoundError: {}", err),
            ManagerError::PKIError(err) => write!(f, "PKIError: {}", err),
            ManagerError::OpenSSL(err) => {
                err
                    .errors()
                    .iter()
                    .try_for_each(|err| write!(f, "Openssl: {}", err))
            }
        }
    }
}