//! Integration tests for cover traffic and query budget.

use blinddex::{
    execute_cover_plan, execute_cover_plan_all, execute_cover_plan_proven, BlindClient,
    BlindDexError, BlindServer, Catalog, CoverPlan, Params, WireQuery, MAX_DECOYS,
};

fn setup_test_catalog() -> (Catalog, BlindServer, BlindClient) {
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params).unwrap();

    for i in 0..8 {
        cat.insert(
            Some(format!("key{}", i)),
            format!("payload for row {}", i).as_bytes(),
        )
        .unwrap();
    }

    let server = BlindServer::from_catalog(&cat).unwrap();
    let client = BlindClient::new(&cat).unwrap();
    (cat, server, client)
}

// === Cover Plan Tests ===

#[test]
fn cover_plan_creates_correct_count() {
    let plan = CoverPlan::new(5, 4, 256, [1u8; 32]).unwrap();
    assert_eq!(plan.total_queries(), 5);
    assert_eq!(plan.decoy_count(), 4);
}

#[test]
fn cover_plan_includes_real_index() {
    let real_index = 42;
    let plan = CoverPlan::new(real_index, 6, 256, [2u8; 32]).unwrap();
    assert!(plan.indices().contains(&real_index));
    assert_eq!(plan.indices()[plan.real_position()], real_index);
}

#[test]
fn cover_plan_indices_are_distinct() {
    let plan = CoverPlan::new(10, 10, 256, [3u8; 32]).unwrap();
    let mut sorted = plan.indices().to_vec();
    sorted.sort();
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(sorted.len(), deduped.len());
}

#[test]
fn cover_plan_is_deterministic() {
    let seed = [77u8; 32];
    let plan1 = CoverPlan::new(5, 8, 256, seed).unwrap();
    let plan2 = CoverPlan::new(5, 8, 256, seed).unwrap();

    assert_eq!(plan1.indices(), plan2.indices());
    assert_eq!(plan1.real_position(), plan2.real_position());
}

#[test]
fn cover_plan_different_seeds_differ() {
    let plan1 = CoverPlan::new(5, 5, 256, [1u8; 32]).unwrap();
    let plan2 = CoverPlan::new(5, 5, 256, [2u8; 32]).unwrap();

    assert_ne!(plan1.indices(), plan2.indices());
}

#[test]
fn cover_plan_rejects_out_of_range_index() {
    let result = CoverPlan::new(256, 3, 256, [1u8; 32]);
    assert!(matches!(result, Err(BlindDexError::IndexOutOfRange { .. })));
}

#[test]
fn cover_plan_rejects_too_many_decoys() {
    let result = CoverPlan::new(0, MAX_DECOYS + 1, 256, [1u8; 32]);
    assert!(matches!(
        result,
        Err(BlindDexError::InvalidBatchSize { .. })
    ));
}

#[test]
fn cover_plan_rejects_more_decoys_than_rows() {
    let result = CoverPlan::new(0, 10, 8, [1u8; 32]);
    assert!(matches!(
        result,
        Err(BlindDexError::InvalidBatchSize { .. })
    ));
}

#[test]
fn cover_plan_zero_decoys() {
    let plan = CoverPlan::new(5, 0, 256, [1u8; 32]).unwrap();
    assert_eq!(plan.total_queries(), 1);
    assert_eq!(plan.indices(), &[5]);
    assert_eq!(plan.real_position(), 0);
}

// === Cover Execution Tests ===

#[test]
fn execute_cover_plan_retrieves_correct_row() {
    let (cat, server, client) = setup_test_catalog();
    let plan = CoverPlan::new(3, 4, cat.params().n_rows, [42u8; 32]).unwrap();

    let row = execute_cover_plan(&client, &server, &plan).unwrap();
    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("payload for row 3"));
}

#[test]
fn execute_cover_plan_all_retrieves_all_rows() {
    let (cat, server, client) = setup_test_catalog();
    let plan = CoverPlan::new(2, 3, cat.params().n_rows, [55u8; 32]).unwrap();

    let results = execute_cover_plan_all(&client, &server, &plan).unwrap();
    assert_eq!(results.len(), plan.total_queries());

    for (i, result) in results.iter().enumerate() {
        assert_eq!(result.index, plan.indices()[i]);
    }

    let real = &results[plan.real_position()];
    let text = String::from_utf8_lossy(&real.row);
    assert!(text.contains("payload for row 2"));
}

#[test]
fn execute_cover_plan_proven_verifies_proof() {
    let (cat, server, client) = setup_test_catalog();
    let plan = CoverPlan::new(1, 2, cat.params().n_rows, [66u8; 32]).unwrap();

    let proven = execute_cover_plan_proven(&client, &server, &plan).unwrap();
    assert_eq!(proven.index, 1);

    proven.proof.verify(&server.merkle_root()).unwrap();

    let text = String::from_utf8_lossy(&proven.row);
    assert!(text.contains("payload for row 1"));
}

// === Query Budget Tests ===

#[test]
fn budget_initial_state() {
    let (_, server, _) = setup_test_catalog();
    let server = server.with_query_budget(100);

    assert!(server.has_query_budget());
    assert_eq!(server.budget_capacity(), Some(100));
    assert_eq!(server.budget_remaining(), Some(100));
}

#[test]
fn budget_consumes_on_query() {
    let (cat, server, client) = setup_test_catalog();
    let server = server.with_query_budget(100);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs);

    let answer = server.answer_wire(&wire_query).unwrap();
    assert_eq!(server.budget_remaining(), Some(99));

    assert!(answer.has_budget_status());
    assert_eq!(answer.budget_status.as_ref().unwrap().remaining, 99);
}

#[test]
fn budget_exhaustion_rejects_queries() {
    let (cat, server, client) = setup_test_catalog();
    let server = server.with_query_budget(3);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs.clone());

    server.answer_wire(&wire_query).unwrap();
    server.answer_wire(&wire_query).unwrap();
    server.answer_wire(&wire_query).unwrap();

    let result = server.answer_wire(&wire_query);
    assert!(matches!(
        result,
        Err(BlindDexError::BudgetExceeded { remaining: 0, .. })
    ));
}

#[test]
fn budget_cover_plan_via_wire() {
    let (cat, server, client) = setup_test_catalog();
    let server = server.with_query_budget(10);

    let plan = CoverPlan::new(0, 3, cat.params().n_rows, [1u8; 32]).unwrap();

    for &idx in plan.indices() {
        let query_limbs = client.engine().query_exact(idx).unwrap();
        let wire_query = WireQuery::new(*cat.params(), query_limbs);
        server.answer_wire(&wire_query).unwrap();
    }

    assert_eq!(server.budget_remaining(), Some(10 - plan.total_queries()));
}

#[test]
fn budget_wire_exceeds_fails() {
    let (cat, server, client) = setup_test_catalog();
    let server = server.with_query_budget(3);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs);

    for _ in 0..6 {
        match server.answer_wire(&wire_query) {
            Ok(_) => {}
            Err(BlindDexError::BudgetExceeded { .. }) => return,
            Err(e) => panic!("unexpected error: {}", e),
        }
    }
    panic!("should have hit budget limit");
}

#[test]
fn budget_independent_epochs() {
    let (_, server, _) = setup_test_catalog();
    let server = server.with_query_budget(10);

    let budget = server.query_budget().unwrap();
    budget.try_consume("epoch_a", 5).unwrap();
    budget.try_consume("epoch_b", 3).unwrap();

    assert_eq!(budget.remaining("epoch_a"), 5);
    assert_eq!(budget.remaining("epoch_b"), 7);
    assert_eq!(budget.remaining("epoch_c"), 10);
}

#[test]
fn budget_refill_restores_capacity() {
    let (cat, server, client) = setup_test_catalog();
    let server = server.with_query_budget(5);

    let query_limbs = client.engine().query_exact(0).unwrap();
    let wire_query = WireQuery::new(*cat.params(), query_limbs);

    for _ in 0..5 {
        server.answer_wire(&wire_query).unwrap();
    }
    assert_eq!(server.budget_remaining(), Some(0));

    let epoch_key = server.merkle_root_hex();
    server.query_budget().unwrap().refill(&epoch_key);
    assert_eq!(server.budget_remaining(), Some(5));
}

// === Combined Features Tests ===

#[test]
fn cover_with_budget_and_replay_protection() {
    let (cat, server, client) = setup_test_catalog();
    let server = server
        .with_query_budget(50)
        .with_default_replay_protection()
        .with_answer_padding(256);

    assert!(server.has_query_budget());
    assert!(server.has_replay_protection());
    assert!(server.has_answer_padding());

    let plan = CoverPlan::new(2, 3, cat.params().n_rows, [88u8; 32]).unwrap();
    let row = execute_cover_plan(&client, &server, &plan).unwrap();

    let text = String::from_utf8_lossy(&row);
    assert!(text.contains("payload for row 2"));

    assert_eq!(server.budget_remaining(), Some(50));
}

#[test]
fn cover_with_wire_queries_consumes_budget() {
    let (cat, server, client) = setup_test_catalog();
    let server = server
        .with_query_budget(50)
        .with_default_replay_protection();

    let plan = CoverPlan::new(2, 3, cat.params().n_rows, [88u8; 32]).unwrap();

    for (i, &idx) in plan.indices().iter().enumerate() {
        let nonce = format!("nonce_{}", i);
        let query_limbs = client.engine().query_exact(idx).unwrap();
        let wire_query = WireQuery::new(*cat.params(), query_limbs).with_nonce(&nonce);
        let answer = server.answer_wire(&wire_query).unwrap();
        assert!(answer.has_budget_status());
    }

    assert_eq!(server.budget_remaining(), Some(50 - plan.total_queries()));
}

#[test]
fn wire_answer_budget_status_roundtrip() {
    use blinddex::WireAnswer;

    let answer = WireAnswer::new(vec![42u64; 8])
        .with_budget_status(95, "abc123def456")
        .with_epoch("seal", "root");

    let json = answer.to_json().unwrap();
    let parsed = WireAnswer::from_json(&json).unwrap();

    assert!(parsed.has_budget_status());
    let status = parsed.budget_status.unwrap();
    assert_eq!(status.remaining, 95);
    assert_eq!(status.epoch_key, "abc123def456");
}
