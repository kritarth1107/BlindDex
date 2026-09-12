//! Offline hint demonstration: generate hint → build query → matvec → recover.
//!
//! This example shows the API shape for SimplePIR-style offline precomputation:
//! 1. Generate a hint from params + seed (offline, can be cached).
//! 2. Build an exact query for a target index.
//! 3. Server computes matvec.
//! 4. Client recovers the row.
//!
//! **Honest scope**: The hint does NOT provide query privacy by itself.
//! This demonstrates the scaffolding for a future LWE layer.
//!
//! Run: `cargo run -p blinddex --example hint_roundtrip`

use blinddex::{BlindServer, Catalog, Hint, Params, PirEngine};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = Params::preset_small();
    println!("params: n_rows={}, row_bytes={}", params.n_rows, params.row_bytes);

    let mut cat = Catalog::new(params)?;
    cat.insert(Some("skill_alpha".into()), b"alpha payload bytes here")?;
    cat.insert(Some("skill_beta".into()), b"beta payload for testing")?;
    cat.insert(Some("tool_gamma".into()), b"gamma opaque blob data")?;
    println!("catalog: {} entries, root={}", cat.len(), cat.merkle_root_hex());

    let seed = [42u8; 32];
    let hint = Hint::generate(&params, seed)?;
    println!(
        "hint: seed={}, fingerprint={}, len={}",
        hint.seed_hex(),
        hint.params_fingerprint_hex(),
        hint.hint_len
    );

    let hint_json = hint.to_json()?;
    let hint2 = Hint::from_json(&hint_json)?;
    assert_eq!(hint, hint2);
    println!("hint JSON roundtrip: ok ({} bytes)", hint_json.len());

    assert!(hint.matches_params(&params));
    let wrong_params = Params::preset_tiny();
    assert!(!hint.matches_params(&wrong_params));
    println!("hint params check: matches=true for correct params");

    let server = BlindServer::from_catalog(&cat)?;
    let engine = PirEngine::new(params)?;

    for target_index in 0..cat.len() {
        let query = engine.query_exact(target_index)?;
        let answer = server.answer(&query)?;
        let row = engine.recover_row(&answer)?;

        let key = cat.get_key(target_index)?.unwrap_or("<none>");
        let text = String::from_utf8_lossy(&row);
        let trimmed = text.trim_end_matches('\0');
        println!(
            "index={} key={} payload={}",
            target_index, key, trimmed
        );
    }

    println!("\nnote: hint is scaffolding; exact query does NOT hide the index");
    println!("      future LWE layer would use hint for offline precomputation");

    Ok(())
}
