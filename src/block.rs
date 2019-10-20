use crate::prelude::*;
use sodiumoxide::randombytes::randombytes_into;
use std::collections::BTreeSet;

pub const BLOCKHASH_BYTES: usize = 32;
new_type! { /// The hash of a `Block`
    public BlockHash(BLOCKHASH_BYTES);
}

pub const CHAINKEY_BYTES: usize = hash::DIGEST_MAX;
new_type! {
    /// A key which is used for kdf purposes
    secret ChainKey(CHAINKEY_BYTES);
}

impl ChainKey {
    fn new() -> Self {
        sodiumoxide::init().expect("failed to initialize libsodium");
        let mut buf = [0u8; CHAINKEY_BYTES];
        randombytes_into(&mut buf);
        ChainKey(buf)
    }
}

impl PartialOrd for ChainKey {
    fn partial_cmp(&self, other: &ChainKey) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ChainKey {
    fn cmp(&self, other: &ChainKey) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

pub const MESSAGEKEY_BYTES: usize = aead::KEYBYTES;
pub type MessageKey = aead::Key;

pub const NONCE_BYTES: usize = aead::NONCEBYTES;
pub type Nonce = aead::Nonce;

pub const SALT_BYTES: usize = 32;
new_type! {
    /// A salt included with blocks, used for hashing
    nonce Salt(SALT_BYTES);
}

impl Salt {
    fn new() -> Salt {
        sodiumoxide::init().expect("failed to initialize libsodium");
        let mut buf = [0u8; SALT_BYTES];
        randombytes_into(&mut buf);
        Salt(buf)
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Block {
    parent_hashes: BTreeSet<BlockHash>,
    salt: Salt,
    sig: sign::Signature,
    tag: aead::Tag,
    #[cfg_attr(feature = "serde_support", serde(with = "serde_bytes"))]
    msg: Vec<u8>,
}

pub struct OpenData {
    pub msg: Vec<u8>,
    pub hash: BlockHash,
    pub key: ChainKey,
}

pub struct SealData {
    pub block: Block,
    pub key: ChainKey,
}

impl Block {
    pub fn compute_hash(&self) -> Option<BlockHash> {
        let mut state = hash::State::new(BLOCKHASH_BYTES, None).ok()?;
        for parent in self.parent_hashes.iter() {
            state.update(parent.as_ref()).ok()?;
        }
        state.update(self.salt.as_ref()).ok()?;
        state.update(self.sig.as_ref()).ok()?;
        // we specifically don't include the message content in the hash for deniability purposes
        let digest = state.finalize().ok()?;
        BlockHash::from_slice(digest.as_ref())
    }

    pub fn seal(
        seckey: &sign::SecretKey,
        parent_keys: BTreeSet<ChainKey>,
        parent_hashes: BTreeSet<BlockHash>,
        mut msg: Vec<u8>,
    ) -> Option<SealData> {
        let salt = Salt::new();
        let dat = compute_block_signing_data(&parent_hashes, salt);
        let sig = sign::sign_detached(&dat, seckey);
        let (c, k, n) = kdf(&parent_keys, salt, sig)?;
        let ad = compute_block_ad(&parent_hashes, salt, sig);
        let tag = aead::seal_detached(&mut msg, Some(&ad), &n, &k);

        Some(SealData {
            block: Block {
                parent_hashes,
                salt,
                sig,
                tag,
                msg,
            },
            key: c,
        })
    }

    pub fn open(
        self,
        signer: &sign::PublicKey,
        parent_keys: BTreeSet<ChainKey>,
    ) -> Result<OpenData, ChainError> {
        let hash = self.compute_hash().ok_or(CryptoError)?;

        let Block {
            parent_hashes,
            salt,
            sig,
            tag,
            mut msg,
        } = self;

        let dat = compute_block_signing_data(&parent_hashes, salt);
        if sign::verify_detached(&sig, &dat, signer) {
            let (c, k, n) = kdf(&parent_keys, salt, sig).ok_or(CryptoError)?;
            let ad = compute_block_ad(&parent_hashes, salt, sig);
            aead::open_detached(&mut msg, Some(&ad), &tag, &n, &k).map_err(|_| DecryptionError)?;
            Ok(OpenData { msg, hash, key: c })
        } else {
            Err(BadSig)
        }
    }
}

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Genesis {
    root: ChainKey,
    sig: sign::Signature,
}

impl Genesis {
    pub fn new(seckey: &sign::SecretKey) -> Self {
        let root = ChainKey::new();
        let sig = sign::sign_detached(root.as_ref(), seckey);
        Genesis { root, sig }
    }

    pub fn compute_hash(&self) -> Option<BlockHash> {
        let mut state = hash::State::new(BLOCKHASH_BYTES, None).ok()?;
        state.update(self.root.as_ref()).ok()?;
        state.update(self.sig.as_ref()).ok()?;
        let digest = state.finalize().ok()?;
        BlockHash::from_slice(digest.as_ref())
    }

    pub fn verify_sig(&self, pk: &sign::PublicKey) -> bool {
        sign::verify_detached(&self.sig, self.root.as_ref(), pk)
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub enum DecryptionResult<S: BlockStore + ?Sized> {
    Success(Vec<u8>, Vec<(Block, S::Signer)>),
    Pending,
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum FoundKeys {
    Found(BTreeSet<ChainKey>),
    Missing(Vec<BlockHash>),
}

pub trait BlockStore {
    type Error: From<ChainError>;
    type Signer: AsRef<sign::PublicKey>;

    /// Stores `key` with index `hash`, removes `hash` from pending lists, and returns list of
    /// `Block`s that are now ready to be decrypted.
    fn store_key(
        &mut self,
        hash: BlockHash,
        key: ChainKey,
    ) -> Result<Vec<(Block, Self::Signer)>, Self::Error>;

    /// Marks all keys in `blocks` as used. Fails if any of them are not found.
    /// Keys marked used should eventually be deleted, with enough margin for error that out of
    /// order message delivery between online clients will not cause issues.
    fn mark_used<'a, I: Iterator<Item = &'a BlockHash>>(
        &mut self,
        blocks: I,
    ) -> Result<(), Self::Error>;

    /// Gets all keys in `blocks`, even if they are marked as used. Does not mark them as used.
    /// Returns `Missing` if any keys were missing, otherwise returns `Found`.
    fn get_keys<'a, I: Iterator<Item = &'a BlockHash>>(
        &self,
        blocks: I,
    ) -> Result<FoundKeys, Self::Error>;

    // Possible we should pause all GC while pending messages exist until we have a better
    // procedure for detecting garbled messages?
    /// Adds `block` to the store marked pending, makes sure hashes it depends on don't get
    /// collected.
    fn add_pending(
        &self,
        signer: &Self::Signer,
        block: Block,
        awaiting: Vec<BlockHash>,
    ) -> Result<(), Self::Error>;

    /// Gets all keys not marked used, does not mark them as used.
    fn get_unused(&self) -> Result<Vec<(BlockHash, ChainKey)>, Self::Error>;
}

pub trait BlockStoreExt: BlockStore {
    /// Checks that `block` is signed by `pubkey`, and returns the decrypted plaintext,
    /// marking all keys referenced by `block` as used.
    fn open_block(
        &mut self,
        signer: &Self::Signer,
        mut block: Block,
    ) -> Result<DecryptionResult<Self>, Self::Error> {
        match self.get_keys(block.parent_hashes.iter())? {
            FoundKeys::Found(keys) => {
                if !sign::verify_detached(
                    &block.sig,
                    &compute_block_signing_data(&block.parent_hashes, block.salt),
                    signer.as_ref(),
                ) {
                    return Err(BadSig.into());
                }

                let (chainkey, msgkey, nonce) =
                    kdf(&keys, block.salt, block.sig).ok_or(CryptoError)?;

                let ad = compute_block_ad(&block.parent_hashes, block.salt, block.sig);

                aead::open_detached(&mut block.msg, Some(&ad), &block.tag, &nonce, &msgkey)
                    .map_err(|_| DecryptionError)?;

                let unlocked = self.store_block_data(&block, chainkey)?;
                Ok(DecryptionResult::Success(block.msg, unlocked))
            }
            FoundKeys::Missing(missing) => {
                self.add_pending(signer, block, missing)?;
                Ok(DecryptionResult::Pending)
            }
        }
    }

    /// Signs `msg` with `seckey`, encrypting it with a symmetric key derived by the results of
    /// `self.get_unused()` and marking all of said keys as used.
    fn seal_block<'a>(
        &mut self,
        seckey: &sign::SecretKey,
        msg: Vec<u8>,
    ) -> Result<Block, Self::Error> {
        let (parent_hashes, keys): (BTreeSet<BlockHash>, BTreeSet<ChainKey>) =
            self.get_unused()?.into_iter().unzip();
        let SealData { block, key } =
            Block::seal(&seckey, keys, parent_hashes, msg).ok_or(CryptoError)?;

        // NOTE: this should never unlock blocks.
        // If it does, one of the following three things has happened:
        // 1) Time travel
        // 2) Broken cryptography
        // 3) Something has gone horribly horribly wrong
        // In any of these cases, I think it's acceptable to panic.
        let unlocked = self.store_block_data(&block, key)?;
        assert!(unlocked.is_empty());

        Ok(block)
    }

    fn store_block_data(
        &mut self,
        block: &Block,
        key: ChainKey,
    ) -> Result<Vec<(Block, Self::Signer)>, Self::Error> {
        let hash = block.compute_hash().ok_or(CryptoError)?;
        let unlocked = self.store_key(hash, key)?;
        self.mark_used(block.parent_hashes.iter())?;
        Ok(unlocked)
    }

    fn store_genesis(&mut self, gen: Genesis) -> Result<(), Self::Error> {
        let hash = gen.compute_hash().ok_or(CryptoError)?;
        self.store_key(hash, gen.root)?;
        Ok(())
    }
}

impl<T: BlockStore> BlockStoreExt for T {}

fn compute_block_signing_data(hashes: &BTreeSet<BlockHash>, salt: Salt) -> Vec<u8> {
    let capacity = hashes.len() * BLOCKHASH_BYTES + SALT_BYTES;
    let mut data = Vec::with_capacity(capacity);
    for hash in hashes {
        data.extend_from_slice(hash.as_ref());
    }
    data.extend_from_slice(salt.as_ref());
    data
}

fn compute_block_ad(parents: &BTreeSet<BlockHash>, salt: Salt, sig: sign::Signature) -> Vec<u8> {
    let capacity = parents.len() * BLOCKHASH_BYTES + SALT_BYTES + sign::SIGNATUREBYTES;
    let mut ad = Vec::with_capacity(capacity);
    for parent in parents.iter() {
        ad.extend_from_slice(parent.as_ref());
    }
    ad.extend_from_slice(salt.as_ref());
    ad.extend_from_slice(sig.as_ref());
    ad
}

fn hash_keys_with_salt_and_index(
    len: usize,
    data: &BTreeSet<ChainKey>,
    salt: Salt,
    sig: sign::Signature,
    idx: u8,
) -> Option<hash::Digest> {
    debug_assert!(
        hash::DIGEST_MIN <= len && len <= hash::DIGEST_MAX,
        "BAD DIGEST LENGTH\nExpected: length between {} and {}\nCalled with {}",
        hash::DIGEST_MIN,
        hash::DIGEST_MAX,
        len
    );
    let mut state = hash::State::new(len, None).ok()?;
    for d in data.iter() {
        state.update(d.as_ref()).ok()?;
    }
    state.update(salt.as_ref()).ok()?;
    state.update(sig.as_ref()).ok()?;
    state.update(&[idx]).ok()?;
    state.finalize().ok()
}

fn kdf(
    keys: &BTreeSet<ChainKey>,
    salt: Salt,
    sig: sign::Signature,
) -> Option<(ChainKey, MessageKey, Nonce)> {
    let chainkey_bytes = hash_keys_with_salt_and_index(CHAINKEY_BYTES, keys, salt, sig, 0)?;
    let msgkey_bytes = hash_keys_with_salt_and_index(MESSAGEKEY_BYTES, keys, salt, sig, 0)?;
    let nonce_bytes = hash_keys_with_salt_and_index(NONCE_BYTES, keys, salt, sig, 0)?;

    let chainkey = ChainKey::from_slice(chainkey_bytes.as_ref())?;
    let msgkey = MessageKey::from_slice(msgkey_bytes.as_ref())?;
    let nonce = Nonce::from_slice(nonce_bytes.as_ref())?;

    Some((chainkey, msgkey, nonce))
}
