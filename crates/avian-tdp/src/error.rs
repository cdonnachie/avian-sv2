use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// A frame whose header or length SRI's framing layer would not accept.
    Framing(framing_sv2::Error),
    /// A payload SRI's binary codec would not deserialize.
    Binary(binary_sv2::Error),
    Secp(secp256k1::Error),
    /// A short, long or otherwise malformed payload in a hand-decoded message.
    Payload(String),
    /// The peer answered something other than what the flow requires next.
    Protocol(String),
    /// The peer declined something and named a reason.
    Refused(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The SRI error types are no_std and implement Debug but not
            // Display, so these two go through Debug.
            Error::Framing(e) => write!(f, "framing: {e:?}"),
            Error::Binary(e) => write!(f, "deserialization: {e:?}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Secp(e) => write!(f, "secp256k1: {e}"),
            Error::Payload(m) => write!(f, "malformed payload: {m}"),
            Error::Protocol(m) => write!(f, "protocol violation: {m}"),
            Error::Refused(m) => write!(f, "refused: {m}"),
        }
    }
}

impl std::error::Error for Error {}

macro_rules! from_error {
    ($from:path => $variant:path) => {
        impl From<$from> for Error {
            fn from(e: $from) -> Self {
                $variant(e)
            }
        }
    };
}

from_error!(std::io::Error => Error::Io);
from_error!(framing_sv2::Error => Error::Framing);
from_error!(binary_sv2::Error => Error::Binary);
from_error!(secp256k1::Error => Error::Secp);

impl From<framing_sv2::framing::SizeHint> for Error {
    fn from(hint: framing_sv2::framing::SizeHint) -> Self {
        Error::Payload(format!("frame is not exactly one frame long: {hint:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
