//! Directory export and keyed blind retrieval demo.
//!
//! Builds a toy catalog, exports a public directory, then retrieves entries
//! by key using the directory for index resolution.
//!
//! Run: `cargo run -p blinddex --example directory_roundtrip`

use blinddex::{BlindClient, BlindServer, Catalog, Directory, Params, WireDirectory};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Directory + Keyed Blind Retrieval Demo ===\n");

    // Build a toy catalog
    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params)?;
    cat.insert(
        Some("wire_transfer".into()),
        b"skill bytes for wire transfer",
    )?;
    cat.insert(Some("calendar".into()), b"calendar sync payload")?;
    cat.insert(Some("email".into()), b"email handler code")?;
    cat.insert(None, b"anonymous payload without key")?;

    println!("Catalog created with {} entries", cat.len());
    println!("merkle_root={}\n", cat.merkle_root_hex());

    // Export the public directory
    let dir = cat.export_directory();
    println!("Directory exported: {} entries", dir.len());
    println!("directory_seal={}\n", dir.seal_hex());

    // Demonstrate that the directory reveals keys but NOT payloads
    println!("Directory entries (public metadata only):");
    for entry in &dir.entries {
        println!(
            "  index={} key={:?} content_hash={}...",
            entry.index,
            entry.key,
            &entry.content_hash[..16]
        );
    }
    println!();

    // Seal verification
    let seal = dir.seal();
    assert!(dir.verify_seal(&seal));
    println!("Seal verified: directory integrity confirmed\n");

    // Wire directory roundtrip (what a host would publish)
    let wire = WireDirectory::from_directory(&dir);
    let wire_json = wire.to_json()?;
    println!(
        "WireDirectory JSON size: {} bytes (includes seal)",
        wire_json.len()
    );
    let wire2 = WireDirectory::from_json(&wire_json)?;
    assert!(wire2.verify_seal());
    println!("WireDirectory roundtrip + seal verify: OK\n");

    // Set up server and client
    let server = BlindServer::from_catalog(&cat)?;
    let client = BlindClient::new(&cat)?;

    // Keyed retrieval via directory (production pattern)
    println!("=== Keyed Blind Retrieval via Directory ===\n");

    let key = "wire_transfer";
    let proven = client.get_blind_proven_by_key_dir(&dir, &server, key)?;
    let text = String::from_utf8_lossy(&proven.row);
    let trimmed = text.trim_end_matches('\0');
    println!("get_blind_proven_by_key_dir('{key}'):");
    println!("  index={}", proven.index);
    println!("  payload={trimmed}");
    println!("  proof_verified=true\n");

    // Hash-keyed retrieval
    let entry = dir.get_by_key("calendar").unwrap();
    let hash = &entry.content_hash;
    let row = client.get_blind_by_hash_dir(&dir, &server, hash)?;
    let text = String::from_utf8_lossy(&row);
    let trimmed = text.trim_end_matches('\0');
    println!("get_blind_by_hash_dir('{hash}'):");
    println!("  index={}", entry.index);
    println!("  payload={trimmed}\n");

    // Local demo pattern (server.catalog() access)
    println!("=== Local Demo: Server Catalog Access ===\n");
    let row = client.get_blind_by_key(&server, "email")?;
    let text = String::from_utf8_lossy(&row);
    let trimmed = text.trim_end_matches('\0');
    println!("get_blind_by_key('email'):");
    println!("  payload={trimmed}");
    println!("  note=local demo only; remote clients use Directory\n");

    // Error handling: unknown key
    println!("=== Error Handling ===\n");
    let result = client.get_blind_by_key_dir(&dir, &server, "nonexistent");
    println!(
        "get_blind_by_key_dir('nonexistent'): {}",
        result.unwrap_err()
    );

    // JSON roundtrip for directory
    let dir_json = dir.to_json()?;
    let dir2 = Directory::from_json(&dir_json)?;
    assert_eq!(dir.seal(), dir2.seal());
    println!("Directory JSON roundtrip: OK (seal stable)\n");

    println!("=== Demo Complete ===");
    println!("note: directory reveals which skills exist (keys + hashes)");
    println!("      with LWE queries, which skill is *fetched* stays private");

    Ok(())
}
