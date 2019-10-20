use super::*;

#[test]
fn seal_unseal() {
    sodiumoxide::init().expect("failed to init sodium");

    // test it many times to make sure the randomness works
    for _ in 0..100 {
        let (pk, sk) = sign::gen_keypair();

        let g1 = Genesis::new(&sk);
        let g2 = Genesis::new(&sk);

        assert!(g1.verify_sig(&pk));
        assert!(g2.verify_sig(&pk));

        let g1hash = g1.compute_hash().expect("failed to compute genesis hash");
        let g2hash = g2.compute_hash().expect("failed to compute genesis hash");
        let g1key = g1.key().clone();
        let g2key = g2.key().clone();

        let m = vec![0u8; 100];
        let mut m_keyset = BTreeSet::new();
        m_keyset.insert(g1key);
        m_keyset.insert(g2key);

        let mut m_hashset = BTreeSet::new();
        m_hashset.insert(g2hash);
        m_hashset.insert(g1hash);

        let m_sealed =
            Block::seal(&sk, &m_keyset, m_hashset.clone(), m.clone()).expect("failed to seal msg");
        let m_hash = m_sealed
            .block
            .compute_hash()
            .expect("failed to compute msg hash");

        let m_unsealed =
            Block::open(m_sealed.block.clone(), &pk, &m_keyset).expect("failed to unseal msg");

        assert_eq!(m_unsealed.msg, m);
        assert_eq!(m_unsealed.hash, m_hash);
        assert_eq!(m_unsealed.key, m_sealed.key);

        assert_eq!(m_sealed.block.parent_hashes, m_hashset);
    }
}
