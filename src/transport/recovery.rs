//! Drain one SSH identity before replacing it; never close an in-use connection.
//!
//! A recovery is requested by a caller, coalesced with other callers for the same
//! target, deferred while a persistent shell (or the requesting operation itself) still
//! owns the connection, and cooled down afterwards so a broken gateway is not hammered.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::Notify;

use crate::errors::{BridgeError, BridgeResult, QueueTimeout};

type ReplaceFuture = Pin<Box<dyn Future<Output = BridgeResult<()>> + Send>>;
type ReplaceFn = Box<dyn FnOnce() -> ReplaceFuture + Send>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Draining,
    PendingSessions,
    Reconnecting,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Draining => "draining",
            Phase::PendingSessions => "pending_sessions",
            Phase::Reconnecting => "reconnecting",
        }
    }
}

struct TargetState {
    generation: u64,
    active: usize,
    phase: Phase,
    cooldown_until: Instant,
    running: bool,
    result: Option<Value>,
}

/// Holds one lease for the lifetime of an operation.
pub struct Lease<'a> {
    recovery: &'a ConnectionRecovery,
    key: String,
    released: bool,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.recovery.release(&self.key);
    }
}

pub struct ConnectionRecovery {
    targets: Mutex<HashMap<String, TargetState>>,
    changed: Notify,
    closing: AtomicBool,
    cooldown_seconds: f64,
    resets: Mutex<u64>,
    failed: Mutex<u64>,
    coalesced: Mutex<u64>,
}

impl ConnectionRecovery {
    pub fn new(cooldown_seconds: f64) -> Arc<Self> {
        Arc::new(Self {
            targets: Mutex::new(HashMap::new()),
            changed: Notify::new(),
            closing: AtomicBool::new(false),
            cooldown_seconds,
            resets: Mutex::new(0),
            failed: Mutex::new(0),
            coalesced: Mutex::new(0),
        })
    }

    fn with_state<T>(&self, key: &str, f: impl FnOnce(&mut TargetState) -> T) -> T {
        let mut targets = self.targets.lock().expect("recovery lock");
        let state = targets.entry(key.to_string()).or_insert(TargetState {
            generation: 0,
            active: 0,
            phase: Phase::Idle,
            cooldown_until: Instant::now(),
            running: false,
            result: None,
        });
        f(state)
    }

    pub fn generation(&self, key: &str) -> u64 {
        self.with_state(key, |state| state.generation)
    }

    pub fn set_generation(&self, key: &str, generation: u64) {
        self.with_state(key, |state| {
            if state.generation != generation {
                state.generation = generation;
                self.changed.notify_waiters();
            }
        });
    }

    pub fn notify(&self, key: &str) {
        self.with_state(key, |_| ());
        self.changed.notify_waiters();
    }

    fn release(&self, key: &str) {
        self.with_state(key, |state| state.active = state.active.saturating_sub(1));
        self.changed.notify_waiters();
    }

    /// Wait until this target is not draining or reconnecting, then hold a lease.
    pub async fn enter(self: &Arc<Self>, key: &str, timeout: f64) -> BridgeResult<Lease<'_>> {
        let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.0));
        loop {
            if self.closing.load(Ordering::SeqCst) {
                return Err(BridgeError::invalid("SSH runner is closing"));
            }
            // One lock for "is this target idle?" and "reserve it": a replacement that
            // starts draining can no longer be overtaken by a new operation.
            let admitted = self.with_state(key, |state| {
                if state.phase == Phase::Idle {
                    state.active += 1;
                    true
                } else {
                    false
                }
            });
            if admitted {
                return Ok(Lease {
                    recovery: self,
                    key: key.to_string(),
                    released: false,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BridgeError::invalid(
                    QueueTimeout {
                        stage: "connection_recovery",
                    }
                    .message(),
                ));
            }
            let _ = tokio::time::timeout(remaining, self.changed.notified()).await;
        }
    }

    /// Ask for a replacement connection, coalescing with other callers.
    pub async fn request(
        self: &Arc<Self>,
        key: &str,
        expected: u64,
        replace: ReplaceFn,
        protected: Arc<dyn Fn() -> bool + Send + Sync>,
        holds_lease: bool,
        wait_seconds: f64,
    ) -> Value {
        if self.closing.load(Ordering::SeqCst) {
            return json!({"status": "unavailable", "reason": "runner_closing"});
        }
        if expected < 1 {
            return json!({"status": "unavailable", "reason": "no_connection_generation"});
        }
        if holds_lease {
            return json!({"status": "deferred", "reason": "current_operation"});
        }
        let start = {
            let mut targets = self.targets.lock().expect("recovery lock");
            let state = targets.entry(key.to_string()).or_insert(TargetState {
                generation: 0,
                active: 0,
                phase: Phase::Idle,
                cooldown_until: Instant::now(),
                running: false,
                result: None,
            });
            if state.running {
                *self.coalesced.lock().expect("counter") += 1;
                false
            } else if state.generation != expected {
                return json!({"status": "already_replaced", "generation": state.generation});
            } else {
                let remaining = state
                    .cooldown_until
                    .saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    return json!({
                        "status": "cooldown",
                        "retry_after_seconds": remaining.as_secs_f64().ceil().max(1.0),
                    });
                }
                state.phase = if protected() {
                    Phase::PendingSessions
                } else {
                    Phase::Draining
                };
                state.running = true;
                state.result = None;
                true
            }
        };
        if start {
            let recovery = self.clone();
            let key = key.to_string();
            let protected_for_task = protected.clone();
            tokio::spawn(async move {
                let outcome = recovery
                    .run_replace(key.clone(), expected, replace, protected_for_task)
                    .await;
                let mut targets = recovery.targets.lock().expect("recovery lock");
                if let Some(state) = targets.get_mut(&key) {
                    state.phase = Phase::Idle;
                    state.running = false;
                    state.result = Some(outcome);
                }
                drop(targets);
                recovery.changed.notify_waiters();
            });
        }
        if protected() {
            return json!({"status": "deferred", "reason": "persistent_shells"});
        }
        self.changed.notify_waiters();
        let deadline = Instant::now() + Duration::from_secs_f64(wait_seconds.max(0.0));
        loop {
            let (running, result, phase, active) = self.with_state(key, |state| {
                (
                    state.running,
                    state.result.clone(),
                    state.phase,
                    state.active,
                )
            });
            if !running {
                if let Some(result) = result {
                    return result;
                }
                return json!({"status": "deferred", "reason": phase.as_str(), "active_uses": active});
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return json!({"status": "deferred", "reason": phase.as_str(), "active_uses": active});
            }
            let _ = tokio::time::timeout(remaining, self.changed.notified()).await;
        }
    }

    async fn run_replace(
        &self,
        key: String,
        expected: u64,
        replace: ReplaceFn,
        protected: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Value {
        // Wait until no operation holds a lease and no persistent shell protects it.
        loop {
            let (generation, _active, should_wait) = self.with_state(&key, |state| {
                (
                    state.generation,
                    state.active,
                    state.active > 0 || protected(),
                )
            });
            if generation != expected {
                return json!({"status": "already_replaced", "generation": generation});
            }
            if !should_wait {
                break;
            }
            self.with_state(&key, |state| {
                state.phase = if protected() {
                    Phase::PendingSessions
                } else {
                    Phase::Draining
                };
            });
            self.changed.notify_waiters();
            // Recheck periodically: a shell can close without sending a notification.
            let _ = tokio::time::timeout(Duration::from_secs(1), self.changed.notified()).await;
        }
        self.with_state(&key, |state| {
            state.phase = Phase::Reconnecting;
            state.cooldown_until = Instant::now() + Duration::from_secs_f64(self.cooldown_seconds);
        });
        self.changed.notify_waiters();
        let started = Instant::now();
        tracing::info!(
            asset = key.as_str(),
            generation = expected,
            "ssh_target_recovery_started"
        );
        match replace().await {
            Ok(()) => {
                *self.resets.lock().expect("counter") += 1;
                let generation = self.with_state(&key, |state| state.generation);
                tracing::info!(
                    asset = key.as_str(),
                    generation,
                    elapsed_seconds = started.elapsed().as_secs_f64(),
                    "ssh_target_recovery_finished"
                );
                json!({"status": "reset", "generation": generation})
            }
            Err(error) => {
                *self.failed.lock().expect("counter") += 1;
                json!({"status": "failed", "error_type": "SshError", "message": error.message()})
            }
        }
    }

    pub fn status(&self) -> Value {
        let targets = self.targets.lock().expect("recovery lock");
        let pending: Vec<Value> = targets
            .iter()
            .filter(|(_, state)| state.phase != Phase::Idle)
            .map(|(key, state)| {
                json!({"target": key, "phase": state.phase.as_str(), "active_uses": state.active})
            })
            .collect();
        json!({
            "resets": *self.resets.lock().expect("counter"),
            "failed": *self.failed.lock().expect("counter"),
            "coalesced": *self.coalesced.lock().expect("counter"),
            "cooldown_seconds": self.cooldown_seconds,
            "pending": pending,
        })
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// A running operation keeps its lease across the remote exchange, so a recovery
    /// requested by *another* channel on the same connection must wait for it.
    #[tokio::test]
    async fn a_replacement_waits_until_the_active_operation_finishes() {
        use std::sync::atomic::AtomicU64;
        let recovery = ConnectionRecovery::new(0.0);
        recovery.set_generation("k", 1);
        let lease = recovery.enter("k", 1.0).await.unwrap();

        let replaced = Arc::new(AtomicU64::new(0));
        let counter = replaced.clone();
        let spawned = recovery
            .request(
                "k",
                1,
                Box::new(move || {
                    let counter = counter.clone();
                    Box::pin(async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                }),
                Arc::new(|| false),
                false,
                2.0,
            )
            .await;
        // `request` returns once the replacement task is scheduled.
        assert!(
            spawned.get("status").is_some(),
            "unexpected request answer: {spawned}"
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            replaced.load(Ordering::SeqCst),
            0,
            "replacement ran while a lease was still held"
        );

        drop(lease);
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            replaced.load(Ordering::SeqCst),
            1,
            "replacement did not run after the lease was released"
        );
    }

    #[tokio::test]
    async fn leases_block_then_release() {
        let recovery = ConnectionRecovery::new(0.0);
        let lease = recovery.enter("k", 1.0).await.unwrap();
        assert_eq!(recovery.with_state("k", |state| state.active), 1);
        drop(lease);
        assert_eq!(recovery.with_state("k", |state| state.active), 0);
    }

    #[tokio::test]
    async fn replace_runs_after_leases_drain_and_reports_reset() {
        let recovery = ConnectionRecovery::new(0.0);
        recovery.set_generation("k", 1);
        let lease = recovery.enter("k", 1.0).await.unwrap();
        let lease_holder = ();
        let calls = Arc::new(AtomicU64::new(0));
        let counter = calls.clone();
        let generation = Arc::new(Mutex::new(1u64));
        let gen_ref = generation.clone();
        let recovery_for_task = recovery.clone();
        let recovery_for_spawn = recovery.clone();
        let _ = &generation;
        let handle = tokio::spawn({
            async move {
                recovery_for_spawn
                    .request(
                        "k",
                        1,
                        Box::new(move || {
                            let counter = counter.clone();
                            let gen_ref = gen_ref.clone();
                            Box::pin(async move {
                                counter.fetch_add(1, Ordering::SeqCst);
                                *gen_ref.lock().unwrap() = 2;
                                Ok(())
                            })
                        }),
                        std::sync::Arc::new(|| false),
                        false,
                        5.0,
                    )
                    .await
            }
        });
        // The replacement must wait for the lease to be released.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(lease);
        let outcome = handle.await.unwrap();
        assert_eq!(outcome["status"], "reset");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(lease_holder);
        let _ = recovery_for_task;
    }

    #[tokio::test]
    async fn stale_generation_is_not_replaced_again() {
        let recovery = ConnectionRecovery::new(0.0);
        recovery.set_generation("k", 3);
        let outcome = recovery
            .request(
                "k",
                1,
                Box::new(|| Box::pin(async { Ok(()) })),
                std::sync::Arc::new(|| false),
                false,
                1.0,
            )
            .await;
        assert_eq!(outcome["status"], "already_replaced");
        assert_eq!(outcome["generation"], 3);
    }

    #[tokio::test]
    async fn persistent_shells_defer_replacement() {
        let recovery = ConnectionRecovery::new(0.0);
        recovery.set_generation("k", 1);
        let outcome = recovery
            .request(
                "k",
                1,
                Box::new(|| Box::pin(async { Ok(()) })),
                std::sync::Arc::new(|| true),
                false,
                0.2,
            )
            .await;
        assert_eq!(outcome["status"], "deferred");
        assert_eq!(outcome["reason"], "persistent_shells");
    }
}
