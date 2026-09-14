//! Tests for epoch-bound query/answer paths.

use blinddex::{BlindClient, BlindServer, Catalog, Params, PinnedEpoch, WireAnswer, WireQuery};

fn make_test_catalog() -> Catalog {
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(Some("skill_a".into()), b"payload for skill a")
        .unwrap();
    cat.insert(Some("skill_b".into()), b"payload for skill b")
        .unwrap();
    cat
}

#[test]
fn epoch_bound_retrieval_success() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = server.export_directory();
    let pinned = PinnedEpoch::from_directory(&dir);

    let row = client.get_blind_epoch(&server, 0, &pinned).unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("payload for skill a"));
}

#[test]
fn epoch_bound_proven_retrieval_success() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = server.export_directory();
    let pinned = PinnedEpoch::from_directory(&dir);

    let proven = client.get_blind_proven_epoch(&server, 0, &pinned).unwrap();
    let text = String::from_utf8_lossy(&proven.row);
    assert!(text.contains("payload for skill a"));
}

#[test]
fn epoch_bound_by_key_success() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = server.export_directory();
    let pinned = PinnedEpoch::from_directory(&dir);

    let row = client
        .get_blind_by_key_epoch(&dir, &server, "skill_b", &pinned)
        .unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("payload for skill b"));
}

#[test]
fn epoch_mismatch_on_query_seal() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let dir = server.export_directory();

    let query = vec![1u64; cat.params().n_rows];
    let wire_query =
        WireQuery::new(*cat.params(), query).with_epoch("wrong_seal", &dir.merkle_root);

    let result = server.answer_wire(&wire_query);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("directory_seal"));
}

#[test]
fn epoch_mismatch_on_query_root() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let dir = server.export_directory();

    let query = vec![1u64; cat.params().n_rows];
    let wire_query = WireQuery::new(*cat.params(), query).with_epoch(&dir.seal_hex(), "wrong_root");

    let result = server.answer_wire(&wire_query);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("merkle_root"));
}

#[test]
fn epoch_mismatch_on_answer() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    let dir = server.export_directory();

    let wrong_pinned = PinnedEpoch::new("wrong_seal", &dir.merkle_root);

    let result = client.get_blind_epoch(&server, 0, &wrong_pinned);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("directory_seal"));
}

#[test]
fn sync_offer_matches_server_epoch() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let dir = server.export_directory();

    let offer = server.sync_offer();
    assert_eq!(offer.merkle_root, server.merkle_root_hex());
    assert_eq!(offer.directory_seal, dir.seal_hex());
    assert_eq!(offer.row_count, cat.len());

    let pinned = PinnedEpoch::from_directory(&dir);
    assert!(offer.verify(&pinned).is_ok());
}

#[test]
fn query_without_epoch_passes() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();

    let query = vec![1u64; cat.params().n_rows];
    let wire_query = WireQuery::new(*cat.params(), query);

    let result = server.answer_wire(&wire_query);
    assert!(result.is_ok());
}

#[test]
fn answer_epoch_fields_populated() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let dir = server.export_directory();

    let query = vec![1u64; cat.params().n_rows];
    let wire_query = WireQuery::new(*cat.params(), query);

    let answer = server.answer_wire(&wire_query).unwrap();
    assert!(answer.has_epoch());
    assert_eq!(answer.directory_seal, Some(dir.seal_hex()));
    assert_eq!(answer.merkle_root, Some(server.merkle_root_hex()));
}

#[test]
fn wire_answer_verify_correct_epoch() {
    let answer = WireAnswer::new(vec![42u64]).with_epoch("seal123", "root456");
    assert!(answer.verify_epoch("seal123", "root456").is_ok());
}

#[test]
fn wire_answer_verify_wrong_epoch() {
    let answer = WireAnswer::new(vec![42u64]).with_epoch("seal123", "root456");
    assert!(answer.verify_epoch("wrong", "root456").is_err());
    assert!(answer.verify_epoch("seal123", "wrong").is_err());
}

#[test]
fn directory_seal_available_on_server() {
    let cat = make_test_catalog();
    let server = BlindServer::from_catalog(&cat).unwrap();
    let dir = cat.export_directory();

    assert_eq!(server.directory_seal_hex(), dir.seal_hex());
    assert_eq!(server.directory_seal(), dir.seal());
}
