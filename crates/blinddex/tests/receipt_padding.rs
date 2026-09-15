//! Integration tests for query receipts (nonce echo) and answer padding.

use blinddex::{
    generate_nonce_hex_default, verify_nonce_echo, BlindClient, BlindDexError, BlindServer,
    Catalog, Params, ReplayWindow, WireAnswer, WireQuery,
};

fn setup_server_client() -> (BlindServer, BlindClient, Catalog) {
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params).unwrap();
    cat.insert(Some("skill_a".into()), b"payload for skill a").unwrap();
    cat.insert(Some("skill_b".into()), b"payload for skill b").unwrap();
    cat.insert(None, b"anonymous payload").unwrap();

    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    (server, client, cat)
}

#[test]
fn nonce_echo_success() {
    let (server, client, cat) = setup_server_client();
    let nonce = generate_nonce_hex_default();

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);

    let wire_answer = server.answer_wire(&wire_query).unwrap();

    assert!(wire_answer.has_nonce());
    assert_eq!(wire_answer.client_nonce.as_deref(), Some(nonce.as_str()));
    assert!(wire_answer.verify_nonce(&nonce).is_ok());
}

#[test]
fn nonce_echo_mismatch() {
    let (server, client, cat) = setup_server_client();
    let nonce = generate_nonce_hex_default();

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);

    let wire_answer = server.answer_wire(&wire_query).unwrap();

    let wrong_nonce = "0000000000000000000000000000000000000000";
    let result = wire_answer.verify_nonce(wrong_nonce);
    assert!(matches!(result, Err(BlindDexError::ReceiptMismatch { .. })));
}

#[test]
fn nonce_missing_in_answer() {
    let answer = WireAnswer::new(vec![42u64; 8]);
    assert!(!answer.has_nonce());

    let result = verify_nonce_echo("abc123", answer.client_nonce.as_deref());
    assert!(matches!(result, Err(BlindDexError::ReceiptMismatch { .. })));
}

#[test]
fn replay_window_rejects_duplicate() {
    let window = ReplayWindow::new(10);

    assert!(window.check_and_record("nonce_1").is_ok());
    assert!(window.check_and_record("nonce_2").is_ok());

    let result = window.check_and_record("nonce_1");
    assert!(matches!(result, Err(BlindDexError::ReplayDetected { .. })));
}

#[test]
fn replay_window_eviction_allows_old_nonce() {
    let window = ReplayWindow::new(3);

    assert!(window.check_and_record("a").is_ok());
    assert!(window.check_and_record("b").is_ok());
    assert!(window.check_and_record("c").is_ok());

    assert!(window.check_and_record("d").is_ok());
    assert!(window.check_and_record("a").is_ok());
}

#[test]
fn server_replay_protection() {
    let (_, _, cat) = setup_server_client();
    let server = BlindServer::from_catalog(&cat)
        .unwrap()
        .with_replay_protection(10);
    let client = BlindClient::new(&cat).unwrap();

    let nonce = generate_nonce_hex_default();
    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs.clone()).with_nonce(&nonce);

    assert!(server.answer_wire(&wire_query).is_ok());

    let wire_query2 = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);
    let result = server.answer_wire(&wire_query2);
    assert!(matches!(result, Err(BlindDexError::ReplayDetected { .. })));
}

#[test]
fn server_replay_allows_different_nonces() {
    let (_, _, cat) = setup_server_client();
    let server = BlindServer::from_catalog(&cat)
        .unwrap()
        .with_replay_protection(10);
    let client = BlindClient::new(&cat).unwrap();

    let query_limbs = client.engine().query_exact(0).unwrap();

    for i in 0..5 {
        let nonce = format!("unique_nonce_{i:016x}");
        let wire_query = WireQuery::new(*cat.params(), query_limbs.clone()).with_nonce(&nonce);
        assert!(server.answer_wire(&wire_query).is_ok());
    }
}

#[test]
fn answer_padding_constant_size() {
    let (server, client, cat) = setup_server_client();
    let server = server.with_answer_padding(256);

    let query0 = client.engine().query_exact(0).unwrap();
    let wire_query0 = WireQuery::new(*cat.params(), query0);
    let answer0 = server.answer_wire(&wire_query0).unwrap();

    let query1 = client.engine().query_exact(1).unwrap();
    let wire_query1 = WireQuery::new(*cat.params(), query1);
    let answer1 = server.answer_wire(&wire_query1).unwrap();

    assert!(answer0.has_padding());
    assert!(answer1.has_padding());

    let padded0 = answer0.padded_answer.as_ref().unwrap();
    let padded1 = answer1.padded_answer.as_ref().unwrap();
    assert_eq!(padded0.len(), padded1.len());
    assert_eq!(padded0.len(), 256 * 2);
}

#[test]
fn answer_padding_strip_verify() {
    let (server, client, cat) = setup_server_client();
    let server = server.with_answer_padding(256);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs);
    let wire_answer = server.answer_wire(&wire_query).unwrap();

    assert!(wire_answer.has_padding());
    let stripped = wire_answer.strip_padding().unwrap();

    let expected: Vec<u8> = wire_answer
        .answer
        .iter()
        .flat_map(|&limb| limb.to_le_bytes())
        .collect();
    assert_eq!(stripped, expected);
}

#[test]
fn answer_padding_invalid_target() {
    let (server, client, cat) = setup_server_client();
    let server = server.with_answer_padding(4);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs);

    let result = server.answer_wire(&wire_query);
    assert!(matches!(result, Err(BlindDexError::PaddingError(_))));
}

#[test]
fn nonce_and_padding_combined() {
    let (_, _, cat) = setup_server_client();
    let server = BlindServer::from_catalog(&cat)
        .unwrap()
        .with_default_replay_protection()
        .with_answer_padding(256);
    let client = BlindClient::new(&cat).unwrap();

    let nonce = generate_nonce_hex_default();
    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);

    let wire_answer = server.answer_wire(&wire_query).unwrap();

    assert!(wire_answer.has_nonce());
    assert!(wire_answer.has_padding());
    assert!(wire_answer.verify_nonce(&nonce).is_ok());

    let row = client.engine().recover_row(&wire_answer.answer).unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.starts_with("payload for skill a"));
}

#[test]
fn wire_query_random_nonce() {
    let params = Params::preset_tiny();
    let query = vec![1u64; params.n_rows];

    let (wire_query, nonce1) = WireQuery::new(params, query.clone()).with_random_nonce();
    assert!(wire_query.has_nonce());
    assert_eq!(nonce1.len(), 32);

    let (wire_query2, nonce2) = WireQuery::new(params, query).with_random_nonce();
    assert_ne!(nonce1, nonce2);
    assert!(wire_query2.has_nonce());
}

#[test]
fn wire_nonce_roundtrip_json() {
    let params = Params::preset_tiny();
    let query = vec![1u64; params.n_rows];
    let nonce = "deadbeef01234567deadbeef01234567";

    let wire_query = WireQuery::new(params, query).with_nonce(nonce);
    let json = wire_query.to_json().unwrap();
    let parsed = WireQuery::from_json(&json).unwrap();

    assert_eq!(wire_query, parsed);
    assert_eq!(parsed.client_nonce, Some(nonce.to_string()));

    let answer = WireAnswer::new(vec![42u64; 8]).with_nonce(nonce);
    let json = answer.to_json().unwrap();
    let parsed = WireAnswer::from_json(&json).unwrap();

    assert_eq!(answer, parsed);
    assert_eq!(parsed.client_nonce, Some(nonce.to_string()));
}

#[test]
fn wire_padding_roundtrip_json() {
    let answer = WireAnswer::new(vec![42u64; 8])
        .with_padding(128)
        .unwrap();

    let json = answer.to_json().unwrap();
    let parsed = WireAnswer::from_json(&json).unwrap();

    assert_eq!(answer.padded_answer, parsed.padded_answer);
    assert_eq!(answer.pad_len, parsed.pad_len);
    assert!(parsed.has_padding());
}

#[test]
fn answer_without_nonce_query_with_nonce() {
    let (server, client, cat) = setup_server_client();

    let nonce = generate_nonce_hex_default();
    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);

    let wire_answer = server.answer_wire(&wire_query).unwrap();
    assert!(wire_answer.has_nonce());
    assert_eq!(wire_answer.client_nonce, Some(nonce));
}

#[test]
fn answer_proven_with_nonce_and_padding() {
    let (_, _, cat) = setup_server_client();
    let server = BlindServer::from_catalog(&cat)
        .unwrap()
        .with_answer_padding(256);
    let client = BlindClient::new(&cat).unwrap();

    let nonce = generate_nonce_hex_default();
    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);

    let (wire_answer, proof) = server.answer_wire_proven(&wire_query, 0).unwrap();

    assert!(wire_answer.has_nonce());
    assert!(wire_answer.has_padding());
    assert!(wire_answer.verify_nonce(&nonce).is_ok());

    proof.verify(&server.merkle_root()).unwrap();
}
