use chainmail::block::*;
use chainmail::errors::{ChainError::*, *};
use sodiumoxide::crypto::sign;
use std::collections::{BTreeSet, HashMap, HashSet};

// TODO: include pending relations here
#[derive(Debug, Eq, PartialEq)]
struct HashStore {
    used: HashSet<BlockHash>,
    unused: HashSet<BlockHash>,
    keys: HashMap<BlockHash, ChainKey>,
}

impl HashStore {
    fn new() -> Self {
        HashStore {
            used: HashSet::new(),
            unused: HashSet::new(),
            keys: HashMap::new(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Signer(sign::PublicKey);

impl AsRef<sign::PublicKey> for Signer {
    fn as_ref(&self) -> &sign::PublicKey {
        &self.0
    }
}

impl BlockStore for HashStore {
    type Signer = Signer;
    type Error = ChainError;

    fn store_key(
        &mut self,
        hash: BlockHash,
        key: ChainKey,
    ) -> Result<Vec<(Block, Signer)>, ChainError> {
        self.keys.insert(hash, key);
        self.unused.insert(hash);
        Ok(Vec::new())
    }

    fn get_keys<'a, I: Iterator<Item = &'a BlockHash>>(
        &self,
        blocks: I,
    ) -> Result<FoundKeys, ChainError> {
        let mut found = BTreeSet::new();
        let mut missing = Vec::new();

        for hash in blocks {
            match self.keys.get(&hash) {
                Some(key) => {
                    found.insert(key.clone());
                }
                None => {
                    missing.push(*hash);
                }
            }
        }

        if missing.is_empty() {
            Ok(FoundKeys::Found(found))
        } else {
            Ok(FoundKeys::Missing(missing))
        }
    }

    fn mark_used<'a, I: Iterator<Item = &'a BlockHash>>(
        &mut self,
        blocks: I,
    ) -> Result<(), Self::Error> {
        for hash in blocks {
            self.unused.remove(hash);
            self.used.insert(*hash);
        }

        Ok(())
    }

    fn add_pending(
        &self,
        _signer: &Self::Signer,
        _block: Block,
        _awaiting: Vec<BlockHash>,
    ) -> Result<(), ChainError> {
        unimplemented!()
    }

    fn get_unused(&self) -> Result<Vec<(BlockHash, ChainKey)>, ChainError> {
        self.unused
            .iter()
            .map(
                |h: &BlockHash| -> Result<(BlockHash, ChainKey), ChainError> {
                    Ok((*h, self.keys.get(h).ok_or(MissingKeys)?.clone()))
                },
            )
            .collect()
    }
}

#[test]
fn seal_unseal() {
    sodiumoxide::init().expect("failed to init sodium");

    let mut store = HashStore::new();
    let (pk, sk) = sign::gen_keypair();
    let signer = Signer(pk);

    let genesis = Genesis::new(&sk);
    store
        .store_genesis(genesis)
        .expect("failed to store genesis block");

    let msg = vec![0u8; 100];
    let block = store
        .seal_block(&sk, msg.clone())
        .expect("failed to seal block");

    let unsealed = store
        .open_block(&signer, block)
        .expect("failed to open block");

    assert_eq!(DecryptionResult::Success(msg, Vec::new()), unsealed);
}
