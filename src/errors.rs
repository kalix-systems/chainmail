use std::{error, fmt};

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    CryptoError,
    MissingKeys,
    DecryptionError,
    BadSig,
}

use Error::*;

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            CryptoError => write!(fmt, "libsodium failed"),
            MissingKeys => write!(fmt, "BlockStore couldn't find keys"),
            DecryptionError => write!(fmt, "Failed to decrypt a block"),
            BadSig => write!(fmt, "Signature did not sign data"),
        }
    }
}

impl error::Error for Error {}
