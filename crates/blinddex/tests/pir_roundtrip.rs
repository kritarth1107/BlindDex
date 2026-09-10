//! PIR matvec round-trip tests (exact one-hot toy path).

use blinddex::{BlindClient, BlindServer, Catalog, DatabaseMatrix, Params, PirEngine};

fn toy_catalog() -> Catalog {
    let params = Params::new(16, 64, 1u64 << 32).unwrap();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(
        Some("wire_transfer".into()),
        b"Your agent downloaded wire_transfer",
    )
    .unwrap();
    cat.insert(Some("invoice_parse".into()), b"invoice_parse skill pack")
        .unwrap();
    cat.insert(Some("calendar".into()), b"calendar.sync opaque blob")
        .unwrap();
    cat.insert(None, b"anonymous-row-3").unwrap();
    cat.insert(Some("mcp.tool.desc".into()), b"{\"name\":\"search\"}")
        .unwrap();
    cat
}

#[test]
fn pir_roundtrip_several_indices() {
    let cat = toy_catalog();
    let engine = PirEngine::new(*cat.params()).unwrap();
    let db = DatabaseMatrix::from_rows(*cat.params(), cat.rows()).unwrap();
    for index in [0usize, 1, 2, 3, 4] {
        let got = engine.retrieve(&db, index).unwrap();
        let expect = cat.get(index).unwrap();
        assert_eq!(got.as_slice(), expect, "mismatch at index {index}");
    }
}

#[test]
fn client_server_get_blind() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    for index in 0..cat.len() {
        let got = client.get_blind(&server, index).unwrap();
        assert_eq!(got.as_slice(), cat.get(index).unwrap());
    }
}

#[test]
fn get_blind_by_hash() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let row = cat.get(1).unwrap();
    let hash = Catalog::content_hash(row);
    let got = client.get_blind_by_hash(&cat, &server, &hash).unwrap();
    assert_eq!(got.as_slice(), row);
}

#[test]
fn merkle_root_matches_server() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    assert_eq!(server.merkle_root(), cat.merkle_root());
}

#[test]
fn bad_query_length_rejected() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let err = server.answer(&[1, 0, 0]).unwrap_err();
    assert!(matches!(
        err,
        blinddex::BlindDexError::BadQueryLength { .. }
    ));
}

#[test]
fn index_out_of_range_on_query() {
    let cat = toy_catalog();
    let engine = PirEngine::new(*cat.params()).unwrap();
    let err = engine.query_exact(cat.params().n_rows).unwrap_err();
    assert!(matches!(
        err,
        blinddex::BlindDexError::IndexOutOfRange { .. }
    ));
}
