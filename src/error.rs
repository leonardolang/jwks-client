use std::fmt::{Display, Formatter};
use std::fmt;

#[derive(Debug)] // , PartialEq)]
pub struct Error {
    /// Debug message associated with error
    pub msg: String,
    pub kind: ErrorKind,
}

/// Type of error encountered
#[derive(Debug)] // , PartialEq)]
pub enum ErrorKind {
    /// An error decoding or validating a token
    JwtDecodeError(Box<jsonwebtoken::errors::ErrorKind>),
    /// Problem with key
    Key,
    /// Could not download key set
    Connection,
    /// Unsupported key type, only RSA is currently supported
    UnsupportedKeyType(String),
    /// Algorithm mismatch - algorithm of token doesn't match intended algorithm of key
    AlgorithmMismatch,
    /// Internal problem (Signals a serious bug or fatal error)
    Internal,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.msg)
    }
}

//impl std::error::Error for Error {
//}

pub mod err {
    use crate::error::Error;
    use crate::error::ErrorKind;

    pub(crate) fn new(msg: String, kind: ErrorKind) -> Error {
        Error { msg, kind }
    }

    pub(crate) fn key(msg: String) -> Error {
        new(msg, ErrorKind::Key)
    }

    pub(crate) fn get(msg: String) -> Error {
        new(msg, ErrorKind::Connection)
    }

    pub(crate) fn int(msg: String) -> Error {
        new(msg, ErrorKind::Internal)
    }

    pub(crate) fn jwt(error: jsonwebtoken::errors::Error) -> Error {
        new(format!("{:?}", error), ErrorKind::JwtDecodeError(Box::new(error.into_kind())))
    }
}

#[cfg(test)]
mod tests {}
