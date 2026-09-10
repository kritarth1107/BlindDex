//! BlindDex CLI: `put` / `get-blind` / `root`.

use blinddex::{BlindClient, BlindServer, Catalog, Params};
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
    /// Print the SHA-256 Merkle root of the catalog.
    Root {
        /// Path to catalog JSON.
        catalog: PathBuf,
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
        Commands::Root { catalog } => {
            let cat = Catalog::load_json(&catalog)?;
            println!("{}", cat.merkle_root_hex());
        }
    }
    Ok(())
}
