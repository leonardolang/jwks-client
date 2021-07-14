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

pub(crate) fn err(msg: String, typ: Type) -> Error {
    Error { msg, typ }
}

pub(crate) fn err_invalid(msg: String) -> Error {
    err(msg, Type::Invalid)
}

pub(crate) fn err_exp(msg: String) -> Error {
    err(msg, Type::Expired)
}

pub(crate) fn err_nbf(msg: String) -> Error {
    err(msg, Type::Early)
}

pub(crate) fn err_cert(msg: String) -> Error {
    err(msg, Type::Certificate)
}

pub(crate) fn err_key(msg: String) -> Error {
    err(msg, Type::Key)
}

pub(crate) fn err_get(msg: String) -> Error {
    err(msg, Type::Connection)
}

pub(crate) fn err_header(msg: String) -> Error {
    err(msg, Type::Header)
}

pub(crate) fn err_payload(msg: String) -> Error {
    err(msg, Type::Payload)
}

pub(crate) fn err_signature(msg: String) -> Error {
    err(msg, Type::Signature)
}

pub(crate) fn err_internal(msg: String) -> Error {
    err(msg, Type::Internal)
}

#[cfg(test)]
mod tests {}
