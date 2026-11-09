//! Error types shared by the bridge.

use serde_json::Value;

/// A user-facing failure. Every variant maps onto the same MCP tool error text;
/// the kind exists so internal callers can distinguish argument mistakes from
/// transport or storage failures.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Inventory(String),
    #[error("{0}")]
    Rest(String),
    #[error("{0}")]
    Storage(String),
    #[error("{0}")]
    Ssh(String),
}

impl BridgeError {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    pub fn inventory(message: impl Into<String>) -> Self {
        Self::Inventory(message.into())
    }

    pub fn rest(message: impl Into<String>) -> Self {
        Self::Rest(message.into())
    }

    pub fn storage(message: impl Into<String>) -> Self {
        Self::Storage(message.into())
    }

    pub fn ssh(message: impl Into<String>) -> Self {
        Self::Ssh(message.into())
    }

    /// Helpers treat a missing record as an argument problem, matching the Python
    /// `ValueError("unknown or expired result_id; ...")` reply.
    pub fn message(&self) -> String {
        self.to_string()
    }
}

impl From<std::io::Error> for BridgeError {
    fn from(value: std::io::Error) -> Self {
        Self::Storage(format!("{}: {}", type_name(&value), value))
    }
}

impl From<serde_json::Error> for BridgeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Storage(format!("json: {value}"))
    }
}

pub type BridgeResult<T> = Result<T, BridgeError>;

fn type_name(value: &std::io::Error) -> &'static str {
    match value.kind() {
        std::io::ErrorKind::NotFound => "NotFound",
        std::io::ErrorKind::PermissionDenied => "PermissionDenied",
        std::io::ErrorKind::AlreadyExists => "AlreadyExists",
        _ => "OSError",
    }
}

/// Per-target refusal that proves the command was never sent.
#[derive(Debug, Clone)]
pub struct QueueFull {
    pub lane: &'static str,
    pub limit: usize,
    pub depth: usize,
}

impl QueueFull {
    pub const STAGE: &'static str = "execution_queue";

    pub fn message(&self) -> String {
        format!(
            "{} execution queue is full ({}/{}); command was not sent",
            self.lane, self.depth, self.limit
        )
    }

    /// Evidence payload merged into a result or execution row.
    pub fn response(&self) -> serde_json::Map<String, Value> {
        let mut out = serde_json::Map::new();
        out.insert("reason".into(), Value::from("queue_full"));
        out.insert("retryable".into(), Value::from(true));
        out.insert(
            "queue".into(),
            serde_json::json!({"lane": self.lane, "limit": self.limit, "depth": self.depth}),
        );
        out
    }
}

/// Waiting for a slot (or a connection drain) timed out. Never sent.
#[derive(Debug, Clone)]
pub struct QueueTimeout {
    pub stage: &'static str,
}

impl QueueTimeout {
    pub fn message(&self) -> String {
        format!("{} timed out; command was not sent", self.stage)
    }
}
