//! Library wire demo: encode/decode Query / Answer / ProvenRow as JSON.
//!
//! Prefer this over a heavyweight HTTP host crate for day-2. An axum/warp
//! `blinddex-host` can wrap the same codec later without changing message shapes.
//!
//! Run: `cargo run -p blinddex --example wire_roundtrip`

use blinddex::{
    BlindClient, BlindServer, Catalog, Params, WireAnswer, WireProvenRow, WireQuery,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = Params::new(8, 64, 1u64 << 32)?;
    let mut cat = Catalog::new(params)?;
    cat.insert(Some("wire_transfer".into()), b"skill bytes for host demo")?;
    cat.insert(Some("calendar".into()), b"calendar.sync")?;

    let server = BlindServer::from_catalog(&cat)?;
    let client = BlindClient::new(&cat)?;
    let engine = client.engine();

    let index = 0usize;
    let query = engine.query_exact(index)?;
    let wq = WireQuery::new(*cat.params(), query.clone());
    let wq_json = wq.to_json()?;
    let wq2 = WireQuery::from_json(&wq_json)?;
    assert_eq!(wq, wq2);

    let answer = server.answer(&wq2.query)?;
    let wa = WireAnswer::new(answer.clone());
    let wa2 = WireAnswer::from_json(&wa.to_json()?)?;
    assert_eq!(wa, wa2);

    let row = engine.recover_row(&wa2.answer)?;
    let proof = server.prove(index)?;
    let proven = WireProvenRow::new(index, &row, &server.merkle_root(), proof);
    proven.verify()?;
    let proven2 = WireProvenRow::from_json(&proven.to_json()?)?;
    proven2.verify()?;

    println!("wire_version={}", blinddex::WIRE_VERSION);
    println!("query_json_bytes={}", wq_json.len());
    println!("answer_limbs={}", wa2.answer.len());
    println!("proven_ok=true");
    println!("merkle_root={}", server.merkle_root_hex());
    println!("note=toy one-hot query; JSON does not add query privacy");
    Ok(())
}
