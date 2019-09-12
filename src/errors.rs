use std::{error, fmt};

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    KdfError,
    MissingKeys,
    DecryptionError,
    HashingError,
    BadSig,
}

use Error::*;

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            KdfError => write!(fmt, "KDF failed"),
            MissingKeys => write!(fmt, "BlockStore couldn't find keys"),
            DecryptionError => write!(fmt, "Failed to decrypt a block"),
            HashingError => write!(fmt, "Failed to hash block"),
            BadSig => write!(fmt, "Signature did not sign data"),
        }
    }
}

impl error::Error for Error {}
