use crate::prelude::*;
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

#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone)]
pub struct Block {
    parent_hashes: BTreeSet<BlockHash>,
    sig: sign::Signature,
    tag: aead::Tag,
    #[cfg_attr(feature = "serde_support", serde(with = "serde_bytes"))]
    msg: Vec<u8>,
}

impl Block {
    pub fn compute_hash(&self) -> Option<BlockHash> {
        let mut state = hash::State::new(BLOCKHASH_BYTES, None).ok()?;
        for parent in self.parent_hashes.iter() {
            state.update(parent.as_ref()).ok()?;
        }
        state.update(self.sig.as_ref()).ok()?;
        // we specifically don't include the message content in the hash for deniability purposes
        let digest = state.finalize().ok()?;
        BlockHash::from_slice(digest.as_ref())
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
        let root = gen_chainkey();
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
pub enum DecryptionResult {
    Success(Vec<u8>, Vec<Block>),
    Pending(Vec<BlockHash>),
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum FoundKeys {
    Found(BTreeSet<ChainKey>),
    Missing(Vec<BlockHash>),
}

pub trait BlockStore {
    type Error: From<ChainError>;

    /// Stores `key` with index `hash`, removes `hash` from pending lists, and returns list of
    /// `Block`s that are now ready to be decrypted.
    fn store_key(&mut self, hash: BlockHash, key: ChainKey) -> Result<Vec<Block>, Self::Error>;

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
    fn add_pending(&self, block: Block, awaiting: Vec<BlockHash>) -> Result<(), Self::Error>;

    /// Gets all keys not marked used, does not mark them as used.
    fn get_unused(&self) -> Result<Vec<(BlockHash, ChainKey)>, Self::Error>;
}

pub trait BlockStoreExt: BlockStore {
    /// Checks that `block` is signed by `pubkey`, and returns the decrypted plaintext,
    /// marking all keys referenced by `block` as used.
    fn open_block(
        &mut self,
        pubkey: &sign::PublicKey,
        mut block: Block,
    ) -> Result<DecryptionResult, Self::Error> {
        match self.get_keys(block.parent_hashes.iter())? {
            FoundKeys::Found(keys) => {
                if !sign::verify_detached(
                    &block.sig,
                    &compute_block_signing_data(block.parent_hashes.iter()),
                    pubkey,
                ) {
                    return Err(BadSig.into());
                }

                let (chainkey, msgkey, nonce) = kdf(keys.iter(), &block.sig).ok_or(CryptoError)?;
                let ad = compute_block_ad(&block.parent_hashes, &block.sig);
                aead::open_detached(&mut block.msg, Some(&ad), &block.tag, &nonce, &msgkey)
                    .map_err(|_| DecryptionError)?;

                let unlocked = self.store_block_data(&block, chainkey)?;
                Ok(DecryptionResult::Success(block.msg, unlocked))
            }
            FoundKeys::Missing(missing) => {
                self.add_pending(block, missing.clone())?;
                Ok(DecryptionResult::Pending(missing))
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
        let (c, block) = seal_block(&seckey, keys.iter(), parent_hashes, msg)?;

        // NOTE: this should never unlock blocks.
        // If it does, one of the following three things has happened:
        // 1) Time travel
        // 2) Broken cryptography
        // 3) Something has gone horribly horribly wrong
        // In any of these cases, I think it's acceptable to panic.
        let unlocked = self.store_block_data(&block, c)?;
        assert!(unlocked.is_empty());

        Ok(block)
    }

    fn store_block_data(
        &mut self,
        block: &Block,
        key: ChainKey,
    ) -> Result<Vec<Block>, Self::Error> {
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

fn seal_block<'a, I: Iterator<Item = &'a ChainKey> + Clone>(
    seckey: &sign::SecretKey,
    parent_keys: I,
    parent_hashes: BTreeSet<BlockHash>,
    mut msg: Vec<u8>,
) -> Result<(ChainKey, Block), ChainError> {
    let dat = compute_block_signing_data(parent_hashes.iter());
    let sig = sign::sign_detached(&dat, seckey);

    let (c, k, n) = kdf(parent_keys, &sig).ok_or(CryptoError)?;
    let ad = compute_block_ad(&parent_hashes, &sig);
    let tag = aead::seal_detached(&mut msg, Some(&ad), &n, &k);

    Ok((
        c,
        Block {
            parent_hashes,
            sig,
            tag,
            msg,
        },
    ))
}

impl<T: BlockStore> BlockStoreExt for T {}

fn compute_block_signing_data<'a, I: Iterator<Item = &'a BlockHash>>(hashes: I) -> Vec<u8> {
    let capacity = hashes.size_hint().0 * BLOCKHASH_BYTES;
    let mut data = Vec::with_capacity(capacity);
    for hash in hashes {
        data.extend_from_slice(hash.as_ref())
    }
    data
}

fn compute_block_ad(parents: &BTreeSet<BlockHash>, sig: &sign::Signature) -> Vec<u8> {
    let capacity = parents.len() * BLOCKHASH_BYTES + sign::SIGNATUREBYTES;
    let mut ad = Vec::with_capacity(capacity);
    for parent in parents.iter() {
        ad.extend_from_slice(parent.as_ref());
    }
    ad.extend_from_slice(sig.as_ref());
    ad
}

fn hash_inputs_with_salt<'a, I, D, S>(len: usize, data: I, salt: &S) -> Result<hash::Digest, ()>
where
    I: Iterator<Item = &'a D>,
    D: AsRef<[u8]> + 'a,
    S: AsRef<[u8]>,
{
    debug_assert!(
        hash::DIGEST_MIN <= len && len <= hash::DIGEST_MAX,
        "BAD DIGEST LENGTH\nExpected: length between {} and {}\nCalled with {}",
        hash::DIGEST_MIN,
        hash::DIGEST_MAX,
        len
    );
    let mut state = hash::State::new(len, None)?;
    for d in data {
        state.update(d.as_ref())?;
    }
    state.update(salt.as_ref())?;
    state.finalize()
}

fn kdf<'a, I: Iterator<Item = &'a ChainKey> + Clone>(
    keys: I,
    sig: &sign::Signature,
) -> Option<(ChainKey, MessageKey, Nonce)> {
    let mut salt = Vec::with_capacity(sign::SIGNATUREBYTES + 1);
    salt.extend_from_slice(sig.as_ref());

    let chainkey_bytes = {
        salt.push(0);
        let res = hash_inputs_with_salt(CHAINKEY_BYTES, keys.clone(), &salt).ok()?;
        salt.pop();
        res
    };
    let msgkey_bytes = {
        salt.push(1);
        let res = hash_inputs_with_salt(MESSAGEKEY_BYTES, keys.clone(), &salt).ok()?;
        salt.pop();
        res
    };
    let nonce_bytes = {
        salt.push(2);
        let res = hash_inputs_with_salt(NONCE_BYTES, keys, &salt).ok()?;
        salt.pop();
        res
    };
    let chainkey = ChainKey::from_slice(chainkey_bytes.as_ref())?;
    let msgkey = MessageKey::from_slice(msgkey_bytes.as_ref())?;
    let nonce = Nonce::from_slice(nonce_bytes.as_ref())?;
    Some((chainkey, msgkey, nonce))
}

fn gen_chainkey() -> ChainKey {
    sodiumoxide::init().expect("failed to initialize libsodium");
    let mut buf = [0u8; CHAINKEY_BYTES];
    sodiumoxide::randombytes::randombytes_into(&mut buf);
    ChainKey(buf)
}
