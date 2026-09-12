//! Simple timing benchmark for PIR matvec operations.
//!
//! This example times the core operations without heavyweight criterion deps:
//! - Database matrix construction
//! - Query generation (exact)
//! - Server matvec
//! - Client row recovery
//!
//! Run: `cargo run -p blinddex --example bench_matvec --release`
//!
//! For best results, run in release mode to measure optimized performance.

use blinddex::{DatabaseMatrix, Params, PirEngine};
use std::time::Instant;

const ITERATIONS: usize = 100;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BlindDex matvec timing (toy PIR)\n");
    println!("Running {} iterations per benchmark...\n", ITERATIONS);

    for (preset_name, params) in [
        ("tiny", Params::preset_tiny()),
        ("small", Params::preset_small()),
        ("medium", Params::preset_medium()),
    ] {
        println!("=== Preset: {} ===", preset_name);
        println!(
            "n_rows={}, row_bytes={}, limbs_per_row={}",
            params.n_rows,
            params.row_bytes,
            params.limbs_per_row()
        );

        let rows: Vec<Vec<u8>> = (0..params.n_rows)
            .map(|i| {
                let mut row = vec![0u8; params.row_bytes];
                for (j, byte) in row.iter_mut().enumerate() {
                    *byte = ((i + j) % 256) as u8;
                }
                row
            })
            .collect();

        let start = Instant::now();
        let db = DatabaseMatrix::from_rows(params, &rows)?;
        let matrix_time = start.elapsed();
        println!("  matrix_build:  {:>8.2?}", matrix_time);

        let engine = PirEngine::new(params)?;

        let start = Instant::now();
        for i in 0..ITERATIONS {
            let idx = i % params.n_rows;
            let _ = engine.query_exact(idx)?;
        }
        let query_time = start.elapsed() / ITERATIONS as u32;
        println!("  query_exact:   {:>8.2?}/op", query_time);

        let query = engine.query_exact(0)?;
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = db.matvec(&query)?;
        }
        let matvec_time = start.elapsed() / ITERATIONS as u32;
        println!("  server_matvec: {:>8.2?}/op", matvec_time);

        let answer = db.matvec(&query)?;
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            let _ = engine.recover_row(&answer)?;
        }
        let recover_time = start.elapsed() / ITERATIONS as u32;
        println!("  recover_row:   {:>8.2?}/op", recover_time);

        let start = Instant::now();
        for i in 0..ITERATIONS {
            let idx = i % params.n_rows;
            let q = engine.query_exact(idx)?;
            let ans = db.matvec(&q)?;
            let _ = engine.recover_row(&ans)?;
        }
        let roundtrip_time = start.elapsed() / ITERATIONS as u32;
        println!("  full_roundtrip:{:>8.2?}/op", roundtrip_time);

        let db_bytes = params.n_rows * params.limbs_per_row() * 8;
        let query_bytes = params.n_rows * 8;
        let answer_bytes = params.limbs_per_row() * 8;
        println!(
            "  sizes: db={}B query={}B answer={}B",
            db_bytes, query_bytes, answer_bytes
        );

        println!();
    }

    println!("Note: These are toy demo sizes. Production SimplePIR uses");
    println!("      larger matrices with LWE noise for actual privacy.");

    Ok(())
}
