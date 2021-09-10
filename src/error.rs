use std::fmt::{Display, Formatter};
use std::fmt;

#[derive(Debug, PartialEq)]
pub struct Error {
    /// Debug message associated with error
    pub msg: String,
    pub typ: Type,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.typ, self.msg)
    }
}

impl std::error::Error for Error {
}

/// Type of error encountered
#[derive(Debug, PartialEq)]
pub enum Type {
    /// Token is invalid
    /// For example, the format of the token is not "HEADER.PAYLOAD.SIGNATURE"
    Invalid,
    /// Token has expired
    Expired,
    /// Not Before (nbf) is set and it's too early to use the token
    Early,
    /// Problem with certificate
    Certificate,
    /// Problem with key
    Key,
    /// Could not download key set
    Connection,
    /// Problem with JWT header
    Header,
    /// Problem with JWT payload
    Payload,
    /// Problem with JWT signature
    Signature,
    /// Internal problem (Signals a serious bug or fatal error)
    Internal,
}

pub mod err {
    use crate::error::{Type, Error};

    pub(crate) fn new(msg: String, typ: Type) -> Error {
        Error { msg, typ }
    }

    pub(crate) fn invalid(msg: String) -> Error {
        new(msg, Type::Invalid)
    }

    pub(crate) fn exp(msg: String) -> Error {
        new(msg, Type::Expired)
    }

    pub(crate) fn nbf(msg: String) -> Error {
        new(msg, Type::Early)
    }

    pub(crate) fn cert(msg: String) -> Error {
        new(msg, Type::Certificate)
    }

    pub(crate) fn key(msg: String) -> Error {
        new(msg, Type::Key)
    }

    pub(crate) fn get(msg: String) -> Error {
        new(msg, Type::Connection)
    }

    pub(crate) fn header(msg: String) -> Error {
        new(msg, Type::Header)
    }

    pub(crate) fn payload(msg: String) -> Error {
        new(msg, Type::Payload)
    }

    pub(crate) fn signature(msg: String) -> Error {
        new(msg, Type::Signature)
    }

    pub(crate) fn internal(msg: String) -> Error {
        new(msg, Type::Internal)
    }
}

#[cfg(test)]
mod tests {}
