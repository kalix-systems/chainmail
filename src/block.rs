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

pub const MESSAGEKEY_BYTES: usize = aead::KEYBYTES;
pub type MessageKey = aead::Key;

pub const NONCE_BYTES: usize = aead::NONCEBYTES;
pub type Nonce = aead::Nonce;

#[derive(Serialize, Deserialize)]
pub struct Block {
    parents: BTreeSet<BlockHash>,
    sig: sign::Signature,
    #[serde(with = "serde_bytes")]
    msg: Vec<u8>,
}

impl Block {
    pub fn compute_hash(&self) -> Option<BlockHash> {
        let mut state = hash::State::new(BLOCKHASH_BYTES, None).ok()?;
        for parent in self.parents.iter() {
            state.update(parent.as_ref()).ok()?;
        }
        state.update(self.sig.as_ref()).ok()?;
        state.update(&self.msg).ok()?;
        let digest = state.finalize().ok()?;
        BlockHash::from_slice(digest.as_ref())
    }
}

fn compute_block_ad<'a, I: Iterator<Item = &'a BlockHash>>(
    parents: I,
    sig: &sign::Signature,
) -> Vec<u8> {
    let capacity = parents.size_hint().0 * BLOCKHASH_BYTES + sign::SIGNATUREBYTES;
    let mut ad = Vec::with_capacity(capacity);
    for parent in parents {
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

fn kdf(keys: &Vec<ChainKey>, salt: &mut Vec<u8>) -> Option<(ChainKey, MessageKey, Nonce)> {
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

pub trait BlockStore {
    fn has_block(&self, hash: BlockHash) -> bool;
    fn get_block(&self, hash: BlockHash) -> Option<Block>;
    fn store_block(&mut self, hash: BlockHash, block: Block) -> bool;
    fn get_keys(&self, hashes: Vec<BlockHash>) -> Option<Vec<ChainKey>>;
    fn store_key(&mut self, hash: BlockHash, key: ChainKey) -> bool;
}

pub trait BlockStoreExt: BlockStore {
    fn open_block(&mut self, block: &Block) -> Result<Vec<u8>, Error> {
        let parents: Vec<BlockHash> = block.parents.iter().map(|x| *x).collect();
        let ad = compute_block_ad(parents.iter(), &block.sig);
        let keys = self.get_keys(parents).ok_or(MissingKeys)?;
        let mut salt = Vec::with_capacity(sign::SIGNATUREBYTES + 1);
        salt.extend_from_slice(block.sig.as_ref());
        let (chainkey, msgkey, nonce) = kdf(&keys, &mut salt).ok_or(KdfError)?;
        let res =
            aead::open(&block.msg, Some(&ad), &nonce, &msgkey).map_err(|_| DecryptionError)?;
        unimplemented!()
    }
}
