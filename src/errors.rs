use std::{error, fmt};

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    CryptoError,
    DecryptionError,
    BadSig,
    MissingKeys,
    BlockStoreSaveError,
    BlockStoreMarkError,
}

use Error::*;

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            CryptoError => write!(fmt, "libsodium failed"),
            DecryptionError => write!(fmt, "Failed to decrypt a block"),
            BadSig => write!(fmt, "Signature did not sign data"),
            MissingKeys => write!(fmt, "BlockStore couldn't find keys"),
            BlockStoreSaveError => write!(fmt, "BlockStore couldn't save key"),
            BlockStoreMarkError => write!(fmt, "BlockStore couldn't mark key as unused"),
        }
    }
}

impl error::Error for Error {}
