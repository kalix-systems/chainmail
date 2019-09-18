use std::{error, fmt};

#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    CryptoError,
    DecryptionError,
    BadSig,
    MissingKeys,
    BlockStoreUnavailable,
    RedundantMark,
}

use Error::*;

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            CryptoError => write!(fmt, "libsodium failed"),
            DecryptionError => write!(fmt, "Failed to decrypt a block"),
            BadSig => write!(fmt, "Signature did not sign data"),
            MissingKeys => write!(fmt, "BlockStore couldn't find keys"),
            BlockStoreUnavailable => write!(fmt, "BlockStore is unavailable"),
            RedundantMark => write!(
                fmt,
                "Tried to mark key as used that was already marked as used."
            ),
        }
    }
}

impl error::Error for Error {}
