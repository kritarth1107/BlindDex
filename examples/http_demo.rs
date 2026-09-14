//! Minimal HTTP server demo for BlindDex.
//!
//! Serves directory, sync offer, and handles PIR queries over HTTP.
//! This is a **toy demo** — not production-ready. No TLS, no auth.
//!
//! # Endpoints
//!
//! - `GET /directory` — returns `WireDirectory` JSON
//! - `GET /sync` — returns `WireSyncOffer` JSON
//! - `POST /query` — accepts `WireQuery` JSON, returns `WireAnswer` JSON
//! - `POST /query-proven` — accepts `WireQuery` JSON + `?index=N`, returns proven row JSON
//!
//! # Running
//!
//! ```bash
//! cargo run -p blinddex --example http_demo
//! ```
//!
//! In another terminal:
//!
//! ```bash
//! # Get directory
//! curl http://localhost:8080/directory
//!
//! # Get sync offer
//! curl http://localhost:8080/sync
//!
//! # Query (you need a valid WireQuery JSON)
//! curl -X POST -H "Content-Type: application/json" \
//!      -d '{"version":1,"params":{"n_rows":16,"row_bytes":32,"modulus":4294967296},"query":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}' \
//!      http://localhost:8080/query
//! ```
//!
//! # Honest scope
//!
//! - No TLS — queries and answers are in cleartext
//! - No authentication — anyone can query
//! - The toy PIR query is still an exact one-hot vector
//! - This demo is for testing the wire protocol, not production use

use blinddex::{
    BlindServer, Catalog, Params, WireDirectory, WireProvenRow, WireQuery, WireSyncOffer,
};
use tiny_http::{Method, Response, Server, StatusCode};

const DEFAULT_PORT: u16 = 8080;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== BlindDex HTTP Demo ===\n");

    let params = Params::preset_tiny();
    let mut cat = Catalog::new(params)?;
    cat.insert(
        Some("wire_transfer".into()),
        b"skill bytes for wire transfer",
    )?;
    cat.insert(Some("calendar".into()), b"calendar sync payload")?;
    cat.insert(Some("email".into()), b"email handler code")?;
    cat.insert(None, b"anonymous payload")?;

    let server = BlindServer::from_catalog(&cat)?;
    let dir = server.export_directory();
    let sync_offer = server.sync_offer();

    println!("Catalog created with {} entries", cat.len());
    println!("Directory seal: {}", dir.seal_hex());
    println!("Merkle root: {}", server.merkle_root_hex());
    println!();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let http = Server::http(format!("0.0.0.0:{port}"))
        .map_err(|e| format!("Failed to bind to port {port}: {e}"))?;

    println!("Server listening on http://0.0.0.0:{port}");
    println!();
    println!("Endpoints:");
    println!("  GET  /directory    — WireDirectory JSON");
    println!("  GET  /sync         — WireSyncOffer JSON");
    println!("  POST /query        — WireQuery → WireAnswer");
    println!("  POST /query-proven — WireQuery + ?index=N → WireProvenRow");
    println!();
    println!("Press Ctrl+C to stop.\n");

    let wire_dir = WireDirectory::from_directory(&dir);
    let wire_sync = WireSyncOffer::from_sync_offer(&sync_offer);

    for mut request in http.incoming_requests() {
        let result = handle_request(&mut request, &server, &wire_dir, &wire_sync);
        match result {
            Ok(response) => {
                let _ = request.respond(response);
            }
            Err((status, msg)) => {
                let response = Response::from_string(msg).with_status_code(status);
                let _ = request.respond(response);
            }
        }
    }

    Ok(())
}

fn handle_request(
    request: &mut tiny_http::Request,
    server: &BlindServer,
    wire_dir: &WireDirectory,
    wire_sync: &WireSyncOffer,
) -> Result<Response<std::io::Cursor<Vec<u8>>>, (StatusCode, String)> {
    let path = request.url().split('?').next().unwrap_or("/");
    let method = request.method().clone();

    println!(
        "{} {} (from {:?})",
        method,
        path,
        request
            .remote_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );

    match (&method, path) {
        (&Method::Get, "/") => {
            let body = "BlindDex HTTP Demo\n\nEndpoints:\n  GET /directory\n  GET /sync\n  POST /query\n  POST /query-proven?index=N";
            Ok(Response::from_string(body).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap(),
            ))
        }

        (&Method::Get, "/directory") => {
            let json = wire_dir
                .to_json()
                .map_err(|e| (StatusCode(500), format!("JSON error: {e}")))?;
            Ok(Response::from_string(json).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            ))
        }

        (&Method::Get, "/sync") => {
            let json = wire_sync
                .to_json()
                .map_err(|e| (StatusCode(500), format!("JSON error: {e}")))?;
            Ok(Response::from_string(json).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            ))
        }

        (&Method::Post, "/query") => {
            let wire_query = read_json_body::<WireQuery>(request)?;

            let wire_answer = server
                .answer_wire(&wire_query)
                .map_err(|e| (StatusCode(400), format!("Query error: {e}")))?;

            let json = wire_answer
                .to_json()
                .map_err(|e| (StatusCode(500), format!("JSON error: {e}")))?;

            Ok(Response::from_string(json).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            ))
        }

        (&Method::Post, "/query-proven") => {
            let query_string = request.url().split('?').nth(1).unwrap_or("");
            let index = parse_index_param(query_string)?;
            let wire_query = read_json_body::<WireQuery>(request)?;

            let (wire_answer, proof) = server
                .answer_wire_proven(&wire_query, index)
                .map_err(|e| (StatusCode(400), format!("Query error: {e}")))?;

            let row = blinddex::pir::PirEngine::new(wire_query.params)
                .map_err(|e| (StatusCode(500), format!("Engine error: {e}")))?
                .recover_row(&wire_answer.answer)
                .map_err(|e| (StatusCode(500), format!("Recovery error: {e}")))?;

            let proven = WireProvenRow::new(index, &row, &server.merkle_root(), proof);
            let json = proven
                .to_json()
                .map_err(|e| (StatusCode(500), format!("JSON error: {e}")))?;

            Ok(Response::from_string(json).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                    .unwrap(),
            ))
        }

        _ => Err((StatusCode(404), "Not Found".to_string())),
    }
}

fn read_json_body<T: serde::de::DeserializeOwned>(
    request: &mut tiny_http::Request,
) -> Result<T, (StatusCode, String)> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .map_err(|e| (StatusCode(400), format!("Read error: {e}")))?;

    serde_json::from_str(&body).map_err(|e| (StatusCode(400), format!("JSON parse error: {e}")))
}

fn parse_index_param(query_string: &str) -> Result<usize, (StatusCode, String)> {
    for pair in query_string.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
            if key == "index" {
                return value
                    .parse()
                    .map_err(|_| (StatusCode(400), "Invalid index parameter".to_string()));
            }
        }
    }
    Err((
        StatusCode(400),
        "Missing index parameter (use ?index=N)".to_string(),
    ))
}
