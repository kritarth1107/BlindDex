//! Merkle commitment consistency tests.

use blinddex::{Catalog, CatalogFileEntry, Params};

#[test]
fn merkle_root_stable_for_same_rows() {
    let params = Params::new(8, 32, 1u64 << 32).unwrap();
    let mut a = Catalog::new(params).unwrap();
    let mut b = Catalog::new(params).unwrap();
    a.insert(Some("wire_transfer".into()), b"skill:wire_transfer v1")
        .unwrap();
    a.insert(Some("calendar".into()), b"skill:calendar sync")
        .unwrap();
    b.insert(Some("wire_transfer".into()), b"skill:wire_transfer v1")
        .unwrap();
    b.insert(Some("calendar".into()), b"skill:calendar sync")
        .unwrap();
    assert_eq!(a.merkle_root(), b.merkle_root());
}

#[test]
fn merkle_root_changes_on_payload_edit() {
    let params = Params::new(8, 32, 1u64 << 32).unwrap();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(Some("k".into()), b"alpha").unwrap();
    let root1 = cat.merkle_root();
    cat.set_at(0, Some("k".into()), b"beta").unwrap();
    let root2 = cat.merkle_root();
    assert_ne!(root1, root2);
}

#[test]
fn content_hash_lookup() {
    let params = Params::new(4, 16, 1u64 << 32).unwrap();
    let mut cat = Catalog::new(params).unwrap();
    let idx = cat.insert(None, b"payload-xyz").unwrap();
    let row = cat.get(idx).unwrap();
    let hash = Catalog::content_hash(row);
    let (found, bytes) = cat.get_by_hash(&hash).unwrap();
    assert_eq!(found, idx);
    assert_eq!(bytes, row);
}

#[test]
fn reject_oversized_catalog_file() {
    let params = Params::new(4, 16, 1u64 << 32).unwrap();
    let entries: Vec<CatalogFileEntry> = (0..5)
        .map(|i| CatalogFileEntry {
            index: i,
            key: None,
            payload: format!("row-{i}"),
        })
        .collect();
    let err = Catalog::from_file_data(params, &entries).unwrap_err();
    assert!(matches!(
        err,
        blinddex::BlindDexError::CatalogTooLarge { got: 5, max: 4 }
    ));
}

#[test]
fn reject_non_power_of_two_n_rows() {
    let err = Params::new(3, 16, 1u64 << 32).unwrap_err();
    assert!(matches!(err, blinddex::BlindDexError::InvalidNRows { .. }));
}

#[test]
fn empty_catalog_has_deterministic_root() {
    let params = Params::new(4, 8, 1u64 << 32).unwrap();
    let a = Catalog::new(params).unwrap();
    let b = Catalog::new(params).unwrap();
    assert_eq!(a.merkle_root_hex(), b.merkle_root_hex());
}
