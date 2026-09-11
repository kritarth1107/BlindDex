//! Merkle inclusion proof verify + tamper failure tests.

use blinddex::{Catalog, MerkleProof, Params, ProofStep, SiblingSide};

fn toy() -> Catalog {
    let params = Params::new(8, 32, 1u64 << 32).unwrap();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(Some("a".into()), b"alpha-row").unwrap();
    cat.insert(Some("b".into()), b"beta-row").unwrap();
    cat.insert(Some("c".into()), b"gamma-row").unwrap();
    cat.insert(None, b"delta-row").unwrap();
    cat
}

#[test]
fn prove_verifies_for_every_occupied_index() {
    let cat = toy();
    let root = cat.merkle_root();
    for i in 0..cat.params().n_rows {
        let proof = cat.prove(i).unwrap();
        proof.verify(&root).unwrap();
        assert_eq!(proof.index, i);
        assert_eq!(proof.leaf_hash, cat.open_leaf_hash(i).unwrap());
    }
}

#[test]
fn tampered_sibling_fails_verify() {
    let cat = toy();
    let root = cat.merkle_root();
    let mut proof = cat.prove(1).unwrap();
    proof.path[0].sibling[0] ^= 0xff;
    let err = proof.verify(&root).unwrap_err();
    assert!(matches!(
        err,
        blinddex::BlindDexError::ProofVerificationFailed { .. }
    ));
}

#[test]
fn tampered_leaf_hash_fails_verify() {
    let cat = toy();
    let root = cat.merkle_root();
    let mut proof = cat.prove(2).unwrap();
    proof.leaf_hash[0] ^= 0xaa;
    assert!(proof.verify(&root).is_err());
}

#[test]
fn wrong_root_rejected() {
    let cat = toy();
    let proof = cat.prove(0).unwrap();
    let mut bad_root = cat.merkle_root();
    bad_root[0] ^= 1;
    assert!(proof.verify(&bad_root).is_err());
}

#[test]
fn proof_json_roundtrip() {
    let cat = toy();
    let proof = cat.prove(3).unwrap();
    let json = blinddex::proof_to_json(&proof).unwrap();
    let back: MerkleProof = blinddex::proof_from_json(&json).unwrap();
    assert_eq!(proof, back);
    back.verify(&cat.merkle_root()).unwrap();
}

#[test]
fn forged_path_length_fails() {
    let cat = toy();
    let root = cat.merkle_root();
    let mut proof = cat.prove(0).unwrap();
    proof.path.push(ProofStep {
        sibling: [0u8; 32],
        side: SiblingSide::Right,
    });
    assert!(proof.verify(&root).is_err());
}
