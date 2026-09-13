//! Tests for directory export and keyed blind retrieval.

use blinddex::{
    BlindClient, BlindServer, Catalog, Directory, Params, WireDirectory,
};

fn make_test_catalog() -> Catalog {
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(Some("wire_transfer".into()), b"skill bytes for wire transfer")
        .unwrap();
    cat.insert(Some("calendar".into()), b"calendar sync payload")
        .unwrap();
    cat.insert(Some("email".into()), b"email handler").unwrap();
    cat.insert(None, b"anonymous payload").unwrap();
    cat
}

#[test]
fn directory_export_roundtrip() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();

    assert_eq!(dir.len(), 4);
    assert_eq!(dir.merkle_root, cat.merkle_root_hex());

    let json = dir.to_json().unwrap();
    let dir2 = Directory::from_json(&json).unwrap();
    assert_eq!(dir, dir2);
}

#[test]
fn directory_seal_stable_across_roundtrip() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();
    let seal = dir.seal();

    let json = dir.to_json().unwrap();
    let dir2 = Directory::from_json(&json).unwrap();

    assert_eq!(dir2.seal(), seal);
    assert!(dir2.verify_seal(&seal));
}

#[test]
fn wire_directory_roundtrip() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();

    let wire = WireDirectory::from_directory(&dir);
    let json = wire.to_json().unwrap();
    let wire2 = WireDirectory::from_json(&json).unwrap();

    assert_eq!(wire, wire2);
    assert!(wire2.verify_seal());

    let dir2 = wire2.to_directory();
    assert_eq!(dir.merkle_root, dir2.merkle_root);
    assert_eq!(dir.entries.len(), dir2.entries.len());
}

#[test]
fn keyed_proven_retrieve_via_directory() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = cat.export_directory();

    let proven = client
        .get_blind_proven_by_key_dir(&dir, &server, "wire_transfer")
        .unwrap();

    assert_eq!(proven.index, 0);
    let text = String::from_utf8_lossy(&proven.row);
    assert!(text.contains("wire transfer"));
}

#[test]
fn keyed_retrieve_via_server_catalog() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();

    let row = client.get_blind_by_key(&server, "calendar").unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("calendar"));

    let proven = client.get_blind_proven_by_key(&server, "email").unwrap();
    assert_eq!(proven.index, 2);
}

#[test]
fn hash_keyed_retrieve_via_directory() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = cat.export_directory();

    let entry = dir.get_by_key("wire_transfer").unwrap();
    let hash = &entry.content_hash;

    let row = client.get_blind_by_hash_dir(&dir, &server, hash).unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("wire transfer"));

    let proven = client
        .get_blind_proven_by_hash_dir(&dir, &server, hash)
        .unwrap();
    assert_eq!(proven.index, 0);
}

#[test]
fn unknown_key_returns_error() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = cat.export_directory();

    let err = client
        .get_blind_by_key_dir(&dir, &server, "nonexistent")
        .unwrap_err();
    assert!(err.to_string().contains("nonexistent"));

    let err = client.get_blind_by_key(&server, "missing").unwrap_err();
    assert!(err.to_string().contains("missing"));
}

#[test]
fn unknown_hash_returns_error() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = cat.export_directory();

    let fake_hash = "0".repeat(64);
    let err = client
        .get_blind_by_hash_dir(&dir, &server, &fake_hash)
        .unwrap_err();
    assert!(err.to_string().contains(&fake_hash));
}

#[test]
fn tampered_seal_detected() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();
    let seal = dir.seal();

    let mut tampered_seal = seal;
    tampered_seal[0] ^= 0x01;

    assert!(!dir.verify_seal(&tampered_seal));
    assert!(!dir.verify_seal_hex(&hex::encode(tampered_seal)));
}

#[test]
fn wire_directory_tampered_seal_detected() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();
    let mut wire = WireDirectory::from_directory(&dir);

    assert!(wire.verify_seal());

    wire.seal = "0".repeat(64);
    assert!(!wire.verify_seal());
}

#[test]
fn directory_resolve_methods() {
    let cat = make_test_catalog();
    let dir = cat.export_directory();

    assert_eq!(dir.resolve_key("wire_transfer"), Some(0));
    assert_eq!(dir.resolve_key("calendar"), Some(1));
    assert_eq!(dir.resolve_key("email"), Some(2));
    assert_eq!(dir.resolve_key("unknown"), None);

    let entry = dir.get_by_key("wire_transfer").unwrap();
    assert_eq!(dir.resolve_hash(&entry.content_hash), Some(0));
    assert_eq!(dir.resolve_hash("bad_hash"), None);
}
