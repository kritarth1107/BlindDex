//! Thin client wrapper: build PIR queries and recover rows.

use crate::catalog::Catalog;
use crate::error::Result;
use crate::pir::{DatabaseMatrix, PirEngine};
use crate::server::BlindServer;

/// Client that talks to a [`BlindServer`] (in-process for this slice).
#[derive(Debug, Clone)]
pub struct BlindClient {
    engine: PirEngine,
}

impl BlindClient {
    /// Construct from catalog params.
    pub fn new(catalog: &Catalog) -> Result<Self> {
        Ok(Self {
            engine: PirEngine::new(*catalog.params())?,
        })
    }

    /// Construct from an explicit engine.
    pub fn from_engine(engine: PirEngine) -> Self {
        Self { engine }
    }

    /// Blind retrieval by row index.
    ///
    /// The server learns neither the index nor the payload **when** the query
    /// is cryptographically protected. This toy slice sends an exact one-hot
    /// vector; see `pir` module docs.
    pub fn get_blind(&self, server: &BlindServer, index: usize) -> Result<Vec<u8>> {
        let query = self.engine.query_exact(index)?;
        let answer = server.answer(&query)?;
        self.engine.recover_row(&answer)
    }

    /// Resolve a content hash to an index via a local catalog view, then PIR.
    ///
    /// Hash→index resolution uses the client's committed catalog copy; the
    /// blind fetch still goes through PIR.
    pub fn get_blind_by_hash(
        &self,
        local: &Catalog,
        server: &BlindServer,
        hash: &str,
    ) -> Result<Vec<u8>> {
        let (index, _) = local.get_by_hash(hash)?;
        self.get_blind(server, index)
    }

    /// Local (non-network) retrieve against a matrix — used by tests.
    pub fn retrieve_local(&self, db: &DatabaseMatrix, index: usize) -> Result<Vec<u8>> {
        self.engine.retrieve(db, index)
    }

    /// Borrow the underlying PIR engine.
    pub fn engine(&self) -> &PirEngine {
        &self.engine
    }
}
