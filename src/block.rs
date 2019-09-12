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

#[derive(Serialize, Deserialize, Clone)]
pub struct Block {
    parent_hashes: BTreeSet<BlockHash>,
    sig: sign::Signature,
    #[serde(with = "serde_bytes")]
    msg: Vec<u8>,
}

impl Block {
    pub fn compute_hash(&self) -> Option<BlockHash> {
        let mut state = hash::State::new(BLOCKHASH_BYTES, None).ok()?;
        for parent in self.parent_hashes.iter() {
            state.update(parent.as_ref()).ok()?;
        }
        state.update(self.sig.as_ref()).ok()?;
        state.update(&self.msg).ok()?;
        let digest = state.finalize().ok()?;
        BlockHash::from_slice(digest.as_ref())
    }

    pub fn check_sig(&self, key: &sign::PublicKey) -> bool {
        sign::verify_detached(
            &self.sig,
            &compute_block_signing_data(&self.parent_hashes),
            key,
        )
    }
}

pub trait BlockStore {
    fn store_key(&mut self, hash: BlockHash, key: ChainKey);
    // we'll want to implement some kind of gc strategy to delete old, used keys
    // maybe run it hourly, or more often if there's lots of activity
    fn mark_used<'a, I: Iterator<Item = &'a BlockHash>>(&self, blocks: I);
    fn get_keys<'a, I: Iterator<Item = &'a BlockHash>>(&self, blocks: I) -> Option<Vec<ChainKey>>;

    // this should *not* mark keys as used
    // it would be a map but we split it each time anyway
    fn get_unused(&self) -> Vec<(BlockHash, ChainKey)>;
}

pub trait BlockStoreExt: BlockStore {
    fn open_block(&mut self, pubkey: &sign::PublicKey, block: Block) -> Result<Vec<u8>, Error> {
        if !block.check_sig(pubkey) {
            return Err(BadSig);
        }

        let keys = self
            .get_keys(block.parent_hashes.iter())
            .ok_or(MissingKeys)?
            .into_iter()
            .collect();

        let (chainkey, msgkey, nonce) = kdf(&keys, &block.sig).ok_or(KdfError)?;
        let ad = compute_block_ad(&block.parent_hashes, &block.sig);
        let res =
            aead::open(&block.msg, Some(&ad), &nonce, &msgkey).map_err(|_| DecryptionError)?;

        self.store_block_data(&block, chainkey)?;
        Ok(res)
    }

    fn seal_block(&mut self, seckey: &sign::SecretKey, msg: &[u8]) -> Result<Block, Error> {
        let hashkeys = self.get_unused();
        let (parent_hashes, keys): (BTreeSet<BlockHash>, BTreeSet<ChainKey>) =
            hashkeys.into_iter().unzip();

        let dat = compute_block_signing_data(&parent_hashes);
        let sig = sign::sign_detached(&dat, seckey);

        let (c, k, n) = kdf(&keys, &sig).ok_or(KdfError)?;
        let ad = compute_block_ad(&parent_hashes, &sig);
        let msg = aead::seal(msg, Some(&ad), &n, &k);
        let block = Block {
            parent_hashes,
            sig,
            msg,
        };

        self.store_block_data(&block, c)?;
        Ok(block)
    }

    fn store_block_data(&mut self, block: &Block, key: ChainKey) -> Result<(), Error> {
        let hash = block.compute_hash().ok_or(HashingError)?;
        self.store_key(hash, key);
        self.mark_used(block.parent_hashes.iter());
        Ok(())
    }
}

impl<T: BlockStore> BlockStoreExt for T {}

fn compute_block_signing_data(parents: &BTreeSet<BlockHash>) -> Vec<u8> {
    let capacity = parents.len() * BLOCKHASH_BYTES;
    let mut data = Vec::with_capacity(capacity);
    for parent in parents.iter() {
        data.extend_from_slice(parent.as_ref())
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

fn kdf(keys: &BTreeSet<ChainKey>, sig: &sign::Signature) -> Option<(ChainKey, MessageKey, Nonce)> {
    let mut salt = Vec::with_capacity(sign::SIGNATUREBYTES + 1);
    salt.extend_from_slice(sig.as_ref());

    let chainkey_bytes = {
        salt.push(0);
        let res = hash_inputs_with_salt(CHAINKEY_BYTES, keys.iter(), &salt).ok()?;
        salt.pop();
        res
    };
    let msgkey_bytes = {
        salt.push(1);
        let res = hash_inputs_with_salt(MESSAGEKEY_BYTES, keys.iter(), &salt).ok()?;
        salt.pop();
        res
    };
    let nonce_bytes = {
        salt.push(2);
        let res = hash_inputs_with_salt(NONCE_BYTES, keys.iter(), &salt).ok()?;
        salt.pop();
        res
    };
    let chainkey = ChainKey::from_slice(chainkey_bytes.as_ref())?;
    let msgkey = MessageKey::from_slice(msgkey_bytes.as_ref())?;
    let nonce = Nonce::from_slice(nonce_bytes.as_ref())?;
    Some((chainkey, msgkey, nonce))
}
