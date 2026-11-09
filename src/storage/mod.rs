//! Durable local state: result outputs and request receipts.

pub mod journal;
pub mod results;

pub use journal::{
    canonical_json, fingerprint_of, NullProgress, ProgressSink, RequestJournal, RequestProgress,
};
pub use results::{atomic_json, now, ResultStore};
