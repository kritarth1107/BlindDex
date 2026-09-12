//! BlindDex CLI: put / get-blind / get-blind-proven / batch-get-blind / prove / root /
//! hint-gen / snapshot / presets.

use blinddex::{
    proof_to_json, BlindClient, BlindServer, Catalog, Hint, Params, SnapshotMeta, WireBatchProven,
    WireProvenRow,
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
    }
    Ok(())
}
