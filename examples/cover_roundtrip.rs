//! Cover traffic + query budget demo.
//!
//! Demonstrates:
//! 1. Creating a cover plan with decoy queries
//! 2. Executing cover plan to retrieve only the real row
//! 3. Server-side query budget enforcement
//! 4. Budget exhaustion handling
//!
//! Run: `cargo run -p blinddex --example cover_roundtrip`

use blinddex::{
    execute_cover_plan, execute_cover_plan_all, execute_cover_plan_proven, BlindClient,
    BlindServer, Catalog, CoverPlan, Params,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Cover Traffic + Query Budget Demo ===\n");

    // Build a toy catalog with some entries
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params)?;

    let entries = [
        ("wire_transfer", "skill bytes for wire transfer"),
        ("calendar", "calendar sync payload"),
        ("email", "email handler code"),
        ("contacts", "contacts API wrapper"),
        ("notes", "notes storage backend"),
        ("weather", "weather forecast service"),
        ("maps", "maps navigation data"),
        ("music", "music streaming client"),
    ];

    for (key, payload) in &entries {
        cat.insert(Some((*key).to_string()), payload.as_bytes())?;
    }

    println!("Catalog created with {} entries", cat.len());
    println!("Merkle root: {}\n", cat.merkle_root_hex());

    // === Part 1: Cover Plan Basics ===
    println!("=== Part 1: Cover Plan Basics ===\n");

    let real_index = 3; // "contacts"
    let decoy_count = 4;
    let seed = [42u8; 32];

    let plan = CoverPlan::new(real_index, decoy_count, params.n_rows, seed)?;

    println!("Cover plan created:");
    println!("  real_index: {}", plan.real_index());
    println!("  decoy_count: {}", plan.decoy_count());
    println!("  total_queries: {}", plan.total_queries());
    println!("  indices: {:?}", plan.indices());
    println!(
        "  real_position: {} (index {} in the list)",
        plan.real_position(),
        plan.indices()[plan.real_position()]
    );
    println!("  seed: {}...", &hex::encode(seed)[..16]);
    println!();

    // === Part 2: Execute Cover Plan ===
    println!("=== Part 2: Execute Cover Plan ===\n");

    let server = BlindServer::from_catalog(&cat)?;
    let client = BlindClient::new(&cat)?;

    // Get only the real row
    let row = execute_cover_plan(&client, &server, &plan)?;
    let text = String::from_utf8_lossy(&row);
    let trimmed = text.trim_end_matches('\0');
    println!("Real row recovered: \"{}\"", trimmed);
    println!("  (key: \"contacts\", index: {})", real_index);
    println!();

    // Get all rows for inspection
    let all_rows = execute_cover_plan_all(&client, &server, &plan)?;
    println!("All retrieved rows ({} total):", all_rows.len());
    for (pos, proven) in all_rows.iter().enumerate() {
        let text = String::from_utf8_lossy(&proven.row);
        let trimmed = text.trim_end_matches('\0');
        let marker = if pos == plan.real_position() {
            " <-- REAL"
        } else {
            " (decoy)"
        };
        println!(
            "  [{}] index={}: \"{}\"{}",
            pos, proven.index, trimmed, marker
        );
    }
    println!();

    // === Part 3: Cover Plan with Proof ===
    println!("=== Part 3: Cover Plan with Proof ===\n");

    let proven = execute_cover_plan_proven(&client, &server, &plan)?;
    println!("Proven row recovered:");
    println!("  index: {}", proven.index);
    let text = String::from_utf8_lossy(&proven.row);
    println!("  payload: \"{}\"", text.trim_end_matches('\0'));
    println!("  leaf_hash: {}...", &proven.proof.leaf_hash_hex()[..16]);
    println!("  proof_verified: true");
    println!();

    // === Part 4: Query Budget ===
    println!("=== Part 4: Query Budget ===\n");

    let budget_capacity = 10;
    let server_with_budget = BlindServer::from_catalog(&cat)?.with_query_budget(budget_capacity);

    println!(
        "Server with query budget: capacity={}",
        server_with_budget.budget_capacity().unwrap()
    );
    println!(
        "Initial remaining: {}",
        server_with_budget.budget_remaining().unwrap()
    );
    println!();

    // Issue some queries
    let small_plan = CoverPlan::new(0, 2, params.n_rows, [1u8; 32])?;
    println!(
        "Issuing {} queries (cover plan with 2 decoys)...",
        small_plan.total_queries()
    );

    execute_cover_plan(&client, &server_with_budget, &small_plan)?;
    println!(
        "Budget remaining after first batch: {}",
        server_with_budget.budget_remaining().unwrap()
    );

    // Issue more queries
    let another_plan = CoverPlan::new(1, 3, params.n_rows, [2u8; 32])?;
    println!("Issuing {} more queries...", another_plan.total_queries());

    execute_cover_plan(&client, &server_with_budget, &another_plan)?;
    println!(
        "Budget remaining after second batch: {}",
        server_with_budget.budget_remaining().unwrap()
    );
    println!();

    // Try to exceed budget
    println!("=== Part 5: Budget Exhaustion ===\n");

    let big_plan = CoverPlan::new(2, 5, params.n_rows, [3u8; 32])?;
    println!(
        "Attempting {} queries (more than remaining budget)...",
        big_plan.total_queries()
    );

    match execute_cover_plan(&client, &server_with_budget, &big_plan) {
        Ok(_) => println!("Queries succeeded (within budget)"),
        Err(blinddex::BlindDexError::BudgetExceeded {
            requested,
            remaining,
            epoch_key,
        }) => {
            println!("Budget exceeded (expected):");
            println!("  requested: {}", requested);
            println!("  remaining: {}", remaining);
            println!("  epoch_key: {}...", &epoch_key[..16]);
        }
        Err(e) => println!("Unexpected error: {}", e),
    }
    println!();

    // === Part 6: Deterministic Cover Plans ===
    println!("=== Part 6: Deterministic Cover Plans ===\n");

    let seed1 = [100u8; 32];
    let plan_a = CoverPlan::new(5, 4, params.n_rows, seed1)?;
    let plan_b = CoverPlan::new(5, 4, params.n_rows, seed1)?;

    println!("Same seed produces identical plans:");
    println!("  plan_a.indices: {:?}", plan_a.indices());
    println!("  plan_b.indices: {:?}", plan_b.indices());
    println!(
        "  equal: {}",
        plan_a.indices() == plan_b.indices() && plan_a.real_position() == plan_b.real_position()
    );
    println!();

    let seed2 = [200u8; 32];
    let plan_c = CoverPlan::new(5, 4, params.n_rows, seed2)?;
    println!("Different seed produces different plan:");
    println!("  plan_c.indices: {:?}", plan_c.indices());
    println!("  different: {}", plan_a.indices() != plan_c.indices());
    println!();

    // === Summary ===
    println!("=== Demo Complete ===\n");
    println!("Cover traffic dilutes which query was real by issuing decoys.");
    println!("IMPORTANT: On the toy one-hot path, the server sees all indices.");
    println!("Cover traffic provides real privacy only with LWE queries.\n");
    println!("Query budget is a demo fairness/anti-spam knob, not authentication.");
    println!("For production, combine with proper auth and rate limiting.\n");

    Ok(())
}
