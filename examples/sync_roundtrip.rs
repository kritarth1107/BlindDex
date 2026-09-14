//! Sync handshake + epoch-bound query demo.
//!
//! Demonstrates the catalog sync workflow:
//! 1. Server creates a SyncOffer from its catalog state
//! 2. Client verifies the offer against a pinned epoch
//! 3. Client issues queries with epoch binding
//! 4. Server and client both verify epoch fields
//!
//! Run: `cargo run -p blinddex --example sync_roundtrip`

use blinddex::{
    BlindClient, BlindServer, Catalog, Params, PinnedEpoch, SyncAck, WireQuery, WireSyncAck,
    WireSyncOffer,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Sync Handshake + Epoch-Bound Query Demo ===\n");

    // Build a toy catalog
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params)?;
    cat.insert(
        Some("wire_transfer".into()),
        b"skill bytes for wire transfer",
    )?;
    cat.insert(Some("calendar".into()), b"calendar sync payload")?;
    cat.insert(Some("email".into()), b"email handler code")?;

    let server = BlindServer::from_catalog(&cat)?;
    let client = BlindClient::new(&cat)?;

    println!("Catalog created with {} entries", cat.len());
    println!("Merkle root: {}", server.merkle_root_hex());
    println!("Directory seal: {}\n", server.directory_seal_hex());

    // Step 1: Server creates a SyncOffer
    println!("=== Step 1: Server creates SyncOffer ===\n");
    let offer = server.sync_offer();
    println!("SyncOffer:");
    println!("  version: {}", offer.version);
    println!("  merkle_root: {}", offer.merkle_root);
    println!("  directory_seal: {}", offer.directory_seal);
    println!("  row_count: {}", offer.row_count);
    println!(
        "  params_fingerprint: {}...",
        &offer.params_fingerprint[..16]
    );
    println!();

    // Wire roundtrip (simulates network transfer)
    let wire_offer = WireSyncOffer::from_sync_offer(&offer);
    let wire_json = wire_offer.to_json()?;
    println!("WireSyncOffer JSON: {} bytes", wire_json.len());

    let received_wire = WireSyncOffer::from_json(&wire_json)?;
    let received_offer = received_wire.to_sync_offer();
    println!("Offer roundtrip: OK\n");

    // Step 2: Client verifies against pinned epoch
    println!("=== Step 2: Client verifies against pinned epoch ===\n");
    let dir = server.export_directory();
    let pinned = PinnedEpoch::from_directory(&dir);

    match received_offer.verify(&pinned) {
        Ok(()) => {
            println!("Verification: PASSED");
            println!("  merkle_root matches");
            println!("  directory_seal matches");
            println!("  params_fingerprint matches");
            println!("  row_count matches\n");
        }
        Err(e) => {
            println!("Verification: FAILED - {}\n", e);
        }
    }

    // Client sends acceptance
    let ack = SyncAck::accept(&offer.directory_seal);
    let wire_ack = WireSyncAck::from_sync_ack(&ack);
    println!(
        "SyncAck: accepted={}, seal={}...\n",
        wire_ack.accepted,
        &wire_ack.accepted_seal.as_ref().unwrap()[..16]
    );

    // Step 3: Epoch-bound queries
    println!("=== Step 3: Epoch-bound queries ===\n");

    let proven = client.get_blind_proven_by_key_epoch(&dir, &server, "wire_transfer", &pinned)?;
    let text = String::from_utf8_lossy(&proven.row);
    let trimmed = text.trim_end_matches('\0');
    println!("get_blind_proven_by_key_epoch('wire_transfer'):");
    println!("  index: {}", proven.index);
    println!("  payload: {}", trimmed);
    println!("  proof_verified: true");
    println!("  epoch_verified: true\n");

    // Step 4: Demonstrate epoch mismatch rejection
    println!("=== Step 4: Epoch mismatch rejection ===\n");

    let wrong_pinned = PinnedEpoch::new("wrong_seal_abc123", &dir.merkle_root);
    let result = client.get_blind_epoch(&server, 0, &wrong_pinned);
    match result {
        Ok(_) => println!("Unexpected success"),
        Err(e) => {
            println!("Query with wrong seal: REJECTED");
            println!("  Error: {}\n", e);
        }
    }

    // Step 5: Show wire query with epoch fields
    println!("=== Step 5: Wire query with epoch fields ===\n");

    let query_limbs = vec![1u64; params.n_rows];
    let wire_query =
        WireQuery::new(params, query_limbs).with_epoch(&pinned.directory_seal, &pinned.merkle_root);

    println!("WireQuery:");
    println!("  version: {}", wire_query.version);
    println!("  has_epoch: {}", wire_query.has_epoch());
    println!(
        "  directory_seal: {}...",
        &wire_query.directory_seal.as_ref().unwrap()[..16]
    );
    println!(
        "  merkle_root: {}...",
        &wire_query.merkle_root.as_ref().unwrap()[..16]
    );
    println!();

    let wire_answer = server.answer_wire(&wire_query)?;
    println!("WireAnswer:");
    println!("  has_epoch: {}", wire_answer.has_epoch());
    println!(
        "  directory_seal: {}...",
        &wire_answer.directory_seal.as_ref().unwrap()[..16]
    );
    println!(
        "  merkle_root: {}...",
        &wire_answer.merkle_root.as_ref().unwrap()[..16]
    );
    println!();

    // Verify answer epoch on client side
    client.verify_answer_epoch(&wire_answer, &pinned)?;
    println!("Client verified answer epoch: OK\n");

    println!("=== Demo Complete ===");
    println!("The sync handshake + epoch binding ensures:");
    println!("  1. Server and client agree on catalog state before queries");
    println!("  2. Stale queries targeting old epochs are rejected");
    println!("  3. Answers from unexpected epochs are detected");
    println!("  4. Epoch fields add no overhead when not used");

    Ok(())
}
