//! BlindDex CLI: put / get-blind / get-blind-proven / batch-get-blind / prove / root /
//! directory / get-blind-key / get-blind-proven-key / get-blind-hash / hint-gen / snapshot /
//! sync-check / presets.

use blinddex::{
    proof_to_json, BlindClient, BlindServer, Catalog, Hint, Params, PinnedEpoch, SnapshotMeta,
    SyncOffer, WireBatchProven, WireDirectory, WireProvenRow, WireSyncOffer,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "blinddex",
    version,
    about = "BlindDex — computational PIR over opaque catalogs (toy SimplePIR-style)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Insert a key/payload into a catalog JSON (creates file if missing).
    Put {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Entry key (e.g. skill name).
        key: String,
        /// Payload string (UTF-8).
        payload: String,
        /// Optional n_rows when creating a new catalog (power of two, ≤ 4096).
        #[arg(long, default_value_t = 256)]
        n_rows: usize,
        /// Optional row_bytes when creating a new catalog (≤ 256).
        #[arg(long, default_value_t = 64)]
        row_bytes: usize,
    },
    /// Retrieve a row via toy PIR (exact one-hot query). Index or blake3 hash.
    GetBlind {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Decimal index or hex blake3 content hash.
        index_or_hash: String,
    },
    /// Blind retrieve + verify Merkle inclusion proof against the catalog root.
    GetBlindProven {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Decimal row index.
        index: usize,
        /// Emit a WireProvenRow JSON blob instead of human text.
        #[arg(long)]
        json: bool,
    },
    /// Batch blind retrieve (one matvec per index) with proofs.
    BatchGetBlind {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Comma-separated decimal indices (max 16).
        indices: String,
        /// Emit WireBatchProven JSON.
        #[arg(long)]
        json: bool,
    },
    /// Emit a Merkle inclusion proof for an index (JSON).
    Prove {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Decimal row index.
        index: usize,
    },
    /// Print the SHA-256 Merkle root of the catalog.
    Root {
        /// Path to catalog JSON.
        catalog: PathBuf,
    },
    /// Export a public directory for name→index resolution.
    Directory {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Output path for directory JSON (default: print to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Emit WireDirectory JSON (includes seal).
        #[arg(long)]
        wire: bool,
    },
    /// Retrieve a row by key via toy PIR (resolves key→index locally).
    GetBlindKey {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Entry key (e.g. skill name).
        key: String,
    },
    /// Retrieve a row by key with Merkle proof verification.
    GetBlindProvenKey {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Entry key (e.g. skill name).
        key: String,
        /// Emit a WireProvenRow JSON blob instead of human text.
        #[arg(long)]
        json: bool,
    },
    /// Retrieve a row by blake3 content hash via toy PIR.
    GetBlindHash {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Blake3 content hash (64-char hex).
        hash: String,
        /// Emit a WireProvenRow JSON blob with proof.
        #[arg(long)]
        proven: bool,
    },
    /// Generate an offline hint file for a catalog (scaffolding, not privacy).
    HintGen {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Output path for hint JSON (default: <catalog>.hint.json).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// 32-byte seed as hex (64 chars). Random if omitted.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Create or print a catalog snapshot (params + merkle root + row count).
    Snapshot {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Write snapshot sidecar file (default: print to stdout).
        #[arg(long)]
        write: bool,
        /// Optional hint seed hex to include in the snapshot.
        #[arg(long)]
        hint_seed: Option<String>,
    },
    /// List available parameter presets.
    Presets,
    /// Check catalog against expected seal/root or a sync-offer JSON.
    SyncCheck {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Expected directory seal (64-char hex).
        #[arg(long)]
        seal: Option<String>,
        /// Expected merkle root (64-char hex).
        #[arg(long)]
        root: Option<String>,
        /// Path to sync-offer JSON file to verify against.
        #[arg(long)]
        offer: Option<PathBuf>,
        /// Emit WireSyncOffer JSON for the catalog.
        #[arg(long)]
        emit: bool,
    },
    /// Emit a SyncOffer JSON for a catalog.
    SyncOffer {
        /// Path to catalog JSON.
        catalog: PathBuf,
        /// Output path for sync-offer JSON (default: print to stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Put {
            catalog,
            key,
            payload,
            n_rows,
            row_bytes,
        } => {
            let mut cat = if catalog.exists() {
                Catalog::load_json(&catalog)?
            } else {
                let params = Params::new(n_rows, row_bytes, blinddex::DEFAULT_MODULUS)?;
                Catalog::new(params)?
            };
            let index = cat.insert(Some(key.clone()), payload.as_bytes())?;
            cat.save_json(&catalog)?;
            let row = cat.get(index)?;
            let hash = Catalog::content_hash(row);
            println!("index={index}");
            println!("key={key}");
            println!("content_hash={hash}");
            println!("merkle_root={}", cat.merkle_root_hex());
        }
        Commands::GetBlind {
            catalog,
            index_or_hash,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;
            let (index, row) = if let Ok(index) = index_or_hash.parse::<usize>() {
                let got = client.get_blind(&server, index)?;
                (index, got)
            } else {
                let hash = index_or_hash.to_lowercase();
                let (index, _) = cat.get_by_hash(&hash)?;
                let got = client.get_blind(&server, index)?;
                (index, got)
            };
            let text = String::from_utf8_lossy(&row);
            let trimmed = text.trim_end_matches('\0');
            println!("index={index}");
            println!("payload={trimmed}");
            println!("content_hash={}", Catalog::content_hash(&row));
            println!("merkle_root={}", server.merkle_root_hex());
        }
        Commands::GetBlindProven {
            catalog,
            index,
            json,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;
            let proven = client.get_blind_proven(&server, index)?;
            if json {
                let wire = WireProvenRow::new(
                    proven.index,
                    &proven.row,
                    &server.merkle_root(),
                    proven.proof,
                );
                println!("{}", wire.to_json()?);
            } else {
                let text = String::from_utf8_lossy(&proven.row);
                let trimmed = text.trim_end_matches('\0');
                println!("index={}", proven.index);
                println!("payload={trimmed}");
                println!("leaf_hash={}", proven.proof.leaf_hash_hex());
                println!("merkle_root={}", server.merkle_root_hex());
                println!("proof_ok=true");
            }
        }
        Commands::BatchGetBlind {
            catalog,
            indices,
            json,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;
            let idxs: Result<Vec<usize>, _> = indices
                .split(',')
                .map(|s| s.trim().parse::<usize>())
                .collect();
            let idxs = idxs.map_err(|e| format!("bad indices list: {e}"))?;
            let batch = client.get_blind_batch(&server, &idxs)?;
            if json {
                let items: Vec<WireProvenRow> = batch
                    .into_iter()
                    .map(|p| WireProvenRow::new(p.index, &p.row, &server.merkle_root(), p.proof))
                    .collect();
                let wire = WireBatchProven {
                    version: blinddex::WIRE_VERSION,
                    items,
                };
                println!("{}", wire.to_json()?);
            } else {
                for p in batch {
                    let text = String::from_utf8_lossy(&p.row);
                    let trimmed = text.trim_end_matches('\0');
                    println!(
                        "index={} payload={} leaf_hash={}",
                        p.index,
                        trimmed,
                        p.proof.leaf_hash_hex()
                    );
                }
                println!("merkle_root={}", server.merkle_root_hex());
                println!("batch_mode=multiple_matvecs");
            }
        }
        Commands::Prove { catalog, index } => {
            let cat = Catalog::load_json(&catalog)?;
            let proof = cat.prove(index)?;
            proof.verify(&cat.merkle_root())?;
            println!("{}", proof_to_json(&proof)?);
        }
        Commands::Root { catalog } => {
            let cat = Catalog::load_json(&catalog)?;
            println!("{}", cat.merkle_root_hex());
        }
        Commands::Directory {
            catalog,
            output,
            wire,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let dir = cat.export_directory();

            let json = if wire {
                let wire_dir = WireDirectory::from_directory(&dir);
                wire_dir.to_json()?
            } else {
                dir.to_json()?
            };

            if let Some(out_path) = output {
                std::fs::write(&out_path, &json)?;
                println!("directory_path={}", out_path.display());
            } else {
                println!("{json}");
            }
            println!("entries={}", dir.len());
            println!("merkle_root={}", dir.merkle_root);
            println!("seal={}", dir.seal_hex());
            println!("note=directory reveals which skills exist; not which is fetched");
        }
        Commands::GetBlindKey { catalog, key } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;

            let row = client.get_blind_by_key(&server, &key)?;
            let (index, _) = server.catalog().get_by_key(&key)?;
            let text = String::from_utf8_lossy(&row);
            let trimmed = text.trim_end_matches('\0');
            println!("key={key}");
            println!("index={index}");
            println!("payload={trimmed}");
            println!("content_hash={}", Catalog::content_hash(&row));
            println!("merkle_root={}", server.merkle_root_hex());
        }
        Commands::GetBlindProvenKey { catalog, key, json } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;

            let proven = client.get_blind_proven_by_key(&server, &key)?;

            if json {
                let wire = WireProvenRow::new(
                    proven.index,
                    &proven.row,
                    &server.merkle_root(),
                    proven.proof,
                );
                println!("{}", wire.to_json()?);
            } else {
                let text = String::from_utf8_lossy(&proven.row);
                let trimmed = text.trim_end_matches('\0');
                println!("key={key}");
                println!("index={}", proven.index);
                println!("payload={trimmed}");
                println!("leaf_hash={}", proven.proof.leaf_hash_hex());
                println!("merkle_root={}", server.merkle_root_hex());
                println!("proof_ok=true");
            }
        }
        Commands::GetBlindHash {
            catalog,
            hash,
            proven,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let server = BlindServer::from_catalog(&cat)?;
            let client = BlindClient::new(&cat)?;

            let hash_lower = hash.to_lowercase();
            let (index, _) = cat.get_by_hash(&hash_lower)?;

            if proven {
                let result = client.get_blind_proven(&server, index)?;
                let wire = WireProvenRow::new(
                    result.index,
                    &result.row,
                    &server.merkle_root(),
                    result.proof,
                );
                println!("{}", wire.to_json()?);
            } else {
                let row = client.get_blind(&server, index)?;
                let text = String::from_utf8_lossy(&row);
                let trimmed = text.trim_end_matches('\0');
                println!("hash={hash_lower}");
                println!("index={index}");
                println!("payload={trimmed}");
                println!("merkle_root={}", server.merkle_root_hex());
            }
        }
        Commands::HintGen {
            catalog,
            output,
            seed,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let seed_bytes: [u8; 32] = if let Some(hex_str) = seed {
                let bytes = hex::decode(&hex_str).map_err(|e| format!("invalid seed hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "seed must be 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    )
                    .into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                let mut arr = [0u8; 32];
                use std::time::{SystemTime, UNIX_EPOCH};
                let nanos = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                let hash = blake3::hash(&nanos.to_le_bytes());
                arr.copy_from_slice(hash.as_bytes());
                arr
            };

            let hint = Hint::generate(cat.params(), seed_bytes)?;
            let out_path = output.unwrap_or_else(|| {
                let stem = catalog
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("catalog");
                let parent = catalog.parent().unwrap_or(std::path::Path::new("."));
                parent.join(format!("{}.hint.json", stem))
            });

            std::fs::write(&out_path, hint.to_json()?)?;
            println!("hint_path={}", out_path.display());
            println!("seed={}", hint.seed_hex());
            println!("params_fingerprint={}", hint.params_fingerprint_hex());
            println!("hint_len={}", hint.hint_len);
            println!("note=offline hint scaffolding; does NOT provide query privacy");
        }
        Commands::Snapshot {
            catalog,
            write,
            hint_seed,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let snap = if let Some(hex_str) = hint_seed {
                let bytes =
                    hex::decode(&hex_str).map_err(|e| format!("invalid hint_seed hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err(format!(
                        "hint_seed must be 32 bytes (64 hex chars), got {}",
                        bytes.len()
                    )
                    .into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                SnapshotMeta::from_catalog_with_hint(&cat, &arr)
            } else {
                SnapshotMeta::from_catalog(&cat)
            };

            if write {
                let sidecar = snap.write_sidecar(&catalog)?;
                println!("snapshot_path={}", sidecar.display());
            } else {
                println!("{}", snap.to_json()?);
            }
        }
        Commands::Presets => {
            println!("Available parameter presets (demo sizes, NOT production LWE):\n");
            for name in Params::preset_names() {
                let p = Params::from_preset_name(name).unwrap();
                println!(
                    "  {:<8}  n_rows={:>4}  row_bytes={:>3}  modulus=2^32",
                    name, p.n_rows, p.row_bytes
                );
            }
            println!("\nUsage: blinddex put <catalog> --preset <name> ...");
            println!("       or use Params::preset_*() in library code");
        }
        Commands::SyncCheck {
            catalog,
            seal,
            root,
            offer,
            emit,
        } => {
            let cat = Catalog::load_json(&catalog)?;
            let dir = cat.export_directory();
            let actual_offer = SyncOffer::from_catalog(&cat);

            if emit {
                let wire = WireSyncOffer::from_sync_offer(&actual_offer);
                println!("{}", wire.to_json()?);
                return Ok(());
            }

            let pinned = if let Some(offer_path) = offer {
                let offer_json = std::fs::read_to_string(&offer_path)?;
                let wire_offer = WireSyncOffer::from_json(&offer_json)?;
                let remote_offer = wire_offer.to_sync_offer();
                PinnedEpoch::new(&remote_offer.merkle_root, &remote_offer.directory_seal)
                    .with_params_fingerprint(&remote_offer.params_fingerprint)
                    .with_row_count(remote_offer.row_count)
            } else if seal.is_some() || root.is_some() {
                let expected_seal = seal.unwrap_or_else(|| dir.seal_hex());
                let expected_root = root.unwrap_or_else(|| dir.merkle_root.clone());
                PinnedEpoch::new(&expected_root, &expected_seal)
            } else {
                println!("catalog_merkle_root={}", cat.merkle_root_hex());
                println!("catalog_seal={}", dir.seal_hex());
                println!("catalog_row_count={}", cat.len());
                println!("catalog_params_fingerprint={}", actual_offer.params_fingerprint);
                println!("note=use --seal and --root to verify, or --offer to compare with remote");
                return Ok(());
            };

            match actual_offer.verify(&pinned) {
                Ok(()) => {
                    println!("sync_check=PASS");
                    println!("merkle_root={}", actual_offer.merkle_root);
                    println!("directory_seal={}", actual_offer.directory_seal);
                    println!("row_count={}", actual_offer.row_count);
                }
                Err(e) => {
                    eprintln!("sync_check=FAIL");
                    eprintln!("error={}", e);
                    return Err(e.into());
                }
            }
        }
        Commands::SyncOffer { catalog, output } => {
            let cat = Catalog::load_json(&catalog)?;
            let offer = SyncOffer::from_catalog(&cat);
            let wire = WireSyncOffer::from_sync_offer(&offer);
            let json = wire.to_json()?;

            if let Some(out_path) = output {
                std::fs::write(&out_path, &json)?;
                println!("sync_offer_path={}", out_path.display());
            } else {
                println!("{json}");
            }
            println!("merkle_root={}", offer.merkle_root);
            println!("directory_seal={}", offer.directory_seal);
            println!("row_count={}", offer.row_count);
        }
    }
    Ok(())
}
