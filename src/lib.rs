//! Resident JumpServer bridge with a compact MCP surface.
//!
//! Ownership rule: SSH connections, persistent shells, request receipts and
//! background workers belong to the runtime; MCP handlers are entry points only.
//! Disconnecting a client therefore never cancels accepted work.

pub mod config;
pub mod errors;
pub mod execution;
pub mod filesystem;
pub mod fsprobe;
pub mod guard;
pub mod inspection;
pub mod inventory;
pub mod jobs;
pub mod mcp;
pub mod rest;
pub mod runtime;
pub mod scheduler;
pub mod schema;
pub mod schemas;
pub mod storage;
pub mod terminal;
pub mod tls;
pub mod transport;
pub mod views;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The instruction line every MCP client sees once.
pub const INSTRUCTIONS: &str =
    "JumpServer: run, fs, terminal, read_result, discover, call, meta.\n\
Use REST-authorized targets. Compact responses omit routine metadata; detail=full restores it.\n\
After a lost reply, query request_status with the original request_id; never blindly replay\n\
uncertain work. allow_dangerous acknowledges only the local guard for an already-authorized\n\
action; it grants no approval and cannot override client or JumpServer denial.\n\
Saved outputs expire by TTL (default 7 days, hourly cleanup); reads do not extend it.\n\
Active results are protected; deduplication receipts are retained separately.";
