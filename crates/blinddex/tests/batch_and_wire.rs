//! Batch retrieval + wire codec round-trip tests.

use blinddex::{
    BlindClient, BlindServer, Catalog, Params, WireAnswer, WireBatchProven, WireProvenRow,
    WireQuery, MAX_BATCH_SIZE,
};

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
fn get_blind_proven_roundtrip() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let proven = client.get_blind_proven(&server, 2).unwrap();
    assert_eq!(proven.row.as_slice(), cat.get(2).unwrap());
    proven.proof.verify(&server.merkle_root()).unwrap();
}

#[test]
fn batch_multiple_matvecs_roundtrip() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let batch = client.get_blind_batch(&server, &[0, 2, 4]).unwrap();
    assert_eq!(batch.len(), 3);
    for p in &batch {
        assert_eq!(p.row.as_slice(), cat.get(p.index).unwrap());
        p.proof.verify(&server.merkle_root()).unwrap();
    }
}

#[test]
fn batch_size_limits() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    assert!(client.get_blind_batch(&server, &[]).is_err());
    let too_many: Vec<usize> = (0..=MAX_BATCH_SIZE).collect();
    assert!(client.get_blind_batch(&server, &too_many).is_err());
}

#[test]
fn wire_query_answer_roundtrip() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let q = client.engine().query_exact(1).unwrap();
    let wq = WireQuery::new(*cat.params(), q.clone());
    let wq2 = WireQuery::from_json(&wq.to_json().unwrap()).unwrap();
    assert_eq!(wq, wq2);
    let ans = server.answer(&wq2.query).unwrap();
    let wa = WireAnswer::new(ans.clone());
    let wa2 = WireAnswer::from_json(&wa.to_json().unwrap()).unwrap();
    let row = client.engine().recover_row(&wa2.answer).unwrap();
    assert_eq!(row.as_slice(), cat.get(1).unwrap());
}

#[test]
fn wire_proven_row_roundtrip_and_verify() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let proven = client.get_blind_proven(&server, 0).unwrap();
    let wire = WireProvenRow::new(
        proven.index,
        &proven.row,
        &server.merkle_root(),
        proven.proof,
    );
    wire.verify().unwrap();
    let back = WireProvenRow::from_json(&wire.to_json().unwrap()).unwrap();
    back.verify().unwrap();
    assert_eq!(back.row_bytes().unwrap(), cat.get(0).unwrap());
}

#[test]
fn wire_batch_verify_all() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let batch = client.get_blind_batch(&server, &[1, 3]).unwrap();
    let items: Vec<_> = batch
        .into_iter()
        .map(|p| WireProvenRow::new(p.index, &p.row, &server.merkle_root(), p.proof))
        .collect();
    let wire = WireBatchProven {
        version: blinddex::WIRE_VERSION,
        items,
    };
    wire.verify_all().unwrap();
    let back = WireBatchProven::from_json(&wire.to_json().unwrap()).unwrap();
    back.verify_all().unwrap();
}

#[test]
fn wire_proven_detects_row_tamper() {
    let cat = toy_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let proven = client.get_blind_proven(&server, 0).unwrap();
    let mut wire = WireProvenRow::new(
        proven.index,
        &proven.row,
        &server.merkle_root(),
        proven.proof,
    );
    // Flip a payload byte in the hex encoding.
    let mut bytes = wire.row_bytes().unwrap();
    bytes[0] ^= 0xff;
    wire.row_hex = hex::encode(bytes);
    assert!(wire.verify().is_err());
}
