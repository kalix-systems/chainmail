#[macro_use]
mod newtype_macros;

pub mod block;
pub mod errors;

mod prelude {
    #[cfg(feature = "serde_support")]
    pub use serde::*;

    pub use sodiumoxide::crypto::aead::xchacha20poly1305_ietf as aead;
    pub use sodiumoxide::crypto::generichash as hash;
    pub use sodiumoxide::crypto::sign;

    pub use crate::errors::{Error::*, *};
}
