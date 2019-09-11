#[derive(Eq, PartialEq, Debug)]
pub enum Error {
    KdfError,
    MissingKeys,
    DecryptionError,
    HashingError,
    BadSig,
    BadBlockDepth,
}
