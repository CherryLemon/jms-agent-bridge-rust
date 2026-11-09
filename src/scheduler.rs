//! Execution capacity: bound active commands independently of authentication.
//!
//! Two lanes share one execution limit. General work must leave the inspection
//! reserve untouched; inspection may use every slot when general work is idle.
//! Authentication never holds a slot, so a cold login cannot starve targets that
//! are already authenticated.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex};
use tokio::time::Instant;

use crate::errors::{QueueFull, QueueTimeout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    General,
    Inspection,
}

impl Lane {
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::General => "general",
            Lane::Inspection => "inspection",
        }
    }

    fn index(self) -> usize {
        match self {
            Lane::General => 0,
            Lane::Inspection => 1,
        }
    }
}

/// Accumulated phase timings for one execution.
#[derive(Debug, Default, Clone)]
pub struct Timings {
    pub queue_seconds: f64,
    pub connection_seconds: f64,
    pub channel_seconds: f64,
    pub execution_seconds: f64,
    pub connection_details: BTreeMap<String, f64>,
}

impl Timings {
    pub fn add_connection(&mut self, name: &str, seconds: f64) {
        *self
            .connection_details
            .entry(name.to_string())
            .or_insert(0.0) += seconds;
    }

    pub fn snapshot(&self) -> Value {
        json!({
            "queue_seconds": round(self.queue_seconds, 3),
            "connection_seconds": round(self.connection_seconds, 3),
            "channel_seconds": round(self.channel_seconds, 3),
            "execution_seconds": round(self.execution_seconds, 3),
        })
    }

    pub fn connection_snapshot(&self) -> Value {
        let mut map = serde_json::Map::new();
        for (key, value) in &self.connection_details {
            map.insert(key.clone(), json!(round(*value, 6)));
        }
        Value::Object(map)
    }
}

pub fn round(value: f64, digits: u32) -> f64 {
    let factor = 10f64.powi(digits as i32);
    (value * factor).round() / factor
}

struct Waiter {
    id: u64,
    lane: Lane,
    granted: bool,
    notify: oneshot::Sender<()>,
}

struct Inner {
    active: [usize; 2],
    waiters: VecDeque<Waiter>,
    queue_full_rejections: [u64; 2],
    peak_active: usize,
}

pub struct ExecutionSlots {
    limit: usize,
    inspection_reserved: usize,
    queue_limits: [usize; 2],
    inner: Mutex<Inner>,
    next_id: AtomicU64,
    /// `Drop` cannot await the async mutex, so release is handed to a pump task.
    release: tokio::sync::mpsc::UnboundedSender<Lane>,
    pump: std::sync::Once,
    releases: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Lane>>>,
}

impl Inner {
    fn release(&mut self, lane: Lane) {
        self.active[lane.index()] = self.active[lane.index()].saturating_sub(1);
    }
}

/// Held for the duration of one command; releasing it wakes the next eligible
/// waiter. Dropping the guard is the only release path.
pub struct SlotGuard {
    slots: Arc<ExecutionSlots>,
    lane: Lane,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Best effort: if the pump is gone the process is shutting down anyway.
        let _ = self.slots.release.send(self.lane);
    }
}

impl ExecutionSlots {
    pub fn new(
        limit: usize,
        inspection_reserved: usize,
        queue_limit: usize,
        inspection_queue_limit: usize,
    ) -> Result<Arc<Self>, String> {
        if limit < 1 {
            return Err("execution limit must be a positive integer".into());
        }
        if inspection_reserved >= limit {
            return Err("inspection_reserved must be in 0..limit-1".into());
        }
        let (release, releases) = tokio::sync::mpsc::unbounded_channel::<Lane>();
        let slots = Arc::new(Self {
            limit,
            inspection_reserved,
            queue_limits: [queue_limit, inspection_queue_limit],
            inner: Mutex::new(Inner {
                active: [0, 0],
                waiters: VecDeque::new(),
                queue_full_rejections: [0, 0],
                peak_active: 0,
            }),
            next_id: AtomicU64::new(1),
            release,
            pump: std::sync::Once::new(),
            releases: std::sync::Mutex::new(Some(releases)),
        });
        Ok(slots)
    }

    /// Start the release pump on first use; construction may happen outside a runtime.
    fn ensure_pump(self: &Arc<Self>) {
        self.pump.call_once(|| {
            let Some(mut releases) = self.releases.lock().expect("pump lock").take() else {
                return;
            };
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                while let Some(lane) = releases.recv().await {
                    let Some(slots) = weak.upgrade() else { return };
                    let mut inner = slots.inner.lock().await;
                    inner.release(lane);
                    slots.wake(&mut inner);
                }
            });
        });
    }

    fn eligible(active: &[usize; 2], lane: Lane, limit: usize, reserved: usize) -> bool {
        let total = active[0] + active[1];
        match lane {
            // Inspection may use the reserve, but not more than the global limit.
            Lane::Inspection => total < limit,
            // General work must stay below the reserve boundary.
            Lane::General => total < limit && active[0] < limit - reserved,
        }
    }

    fn wake(&self, inner: &mut Inner) {
        if inner.waiters.is_empty() {
            return;
        }
        let mut index = 0;
        while index < inner.waiters.len() {
            let lane = inner.waiters[index].lane;
            if !Self::eligible(&inner.active, lane, self.limit, self.inspection_reserved) {
                index += 1;
                continue;
            }
            let mut waiter = inner.waiters.remove(index).expect("index in range");
            inner.active[lane.index()] += 1;
            inner.peak_active = inner.peak_active.max(inner.active[0] + inner.active[1]);
            waiter.granted = true;
            let _ = waiter.notify.send(());
        }
    }

    /// Acquire one execution slot, waiting at most `timeout`.
    ///
    /// `timings.queue_seconds` is charged for the wait, matching the Python
    /// scheduler so that remaining queue budget can be recomputed by callers.
    pub async fn acquire(
        self: &Arc<Self>,
        lane: Lane,
        timeout: Duration,
        timings: &mut Timings,
    ) -> Result<SlotGuard, SlotWait> {
        if timeout.is_zero() {
            return Err(SlotWait::Timeout(QueueTimeout {
                stage: "execution_queue",
            }));
        }
        self.ensure_pump();
        let started = Instant::now();
        let (tx, rx) = oneshot::channel();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut inner = self.inner.lock().await;
            self.wake(&mut inner);
            let depth = inner.waiters.iter().filter(|w| w.lane == lane).count();
            if !Self::eligible(&inner.active, lane, self.limit, self.inspection_reserved)
                && depth >= self.queue_limits[lane.index()]
            {
                inner.queue_full_rejections[lane.index()] += 1;
                return Err(SlotWait::Full(QueueFull {
                    lane: lane.as_str(),
                    limit: self.queue_limits[lane.index()],
                    depth,
                }));
            }
            // No await between admission and append: concurrent arrivals cannot
            // overbook waiting capacity, and immediate grants skip the queue.
            inner.waiters.push_back(Waiter {
                id,
                lane,
                granted: false,
                notify: tx,
            });
            self.wake(&mut inner);
        }
        let result = tokio::time::timeout(timeout, rx).await;
        timings.queue_seconds += started.elapsed().as_secs_f64();
        if let Ok(Ok(())) = result {
            return Ok(SlotGuard {
                slots: self.clone(),
                lane,
            });
        }
        // Deadline expired (or the grant sender vanished): retract our waiter. A
        // grant that raced the deadline still counts, so release it explicitly.
        let mut inner = self.inner.lock().await;
        if let Some(position) = inner.waiters.iter().position(|w| w.id == id) {
            let waiter = inner.waiters.remove(position).expect("index in range");
            if waiter.granted {
                inner.active[lane.index()] = inner.active[lane.index()].saturating_sub(1);
                self.wake(&mut inner);
            }
        }
        Err(SlotWait::Timeout(QueueTimeout {
            stage: "execution_queue",
        }))
    }

    pub async fn status(&self) -> Value {
        let inner = self.inner.lock().await;
        let queued_general = inner
            .waiters
            .iter()
            .filter(|w| w.lane == Lane::General)
            .count();
        let queued_inspection = inner
            .waiters
            .iter()
            .filter(|w| w.lane == Lane::Inspection)
            .count();
        json!({
            "limit": self.limit,
            "inspection_reserved": self.inspection_reserved,
            "general_limit": self.limit - self.inspection_reserved,
            "active": {"general": inner.active[0], "inspection": inner.active[1]},
            "queued": {"general": queued_general, "inspection": queued_inspection},
            "queue_limits": {
                "general": self.queue_limits[0],
                "inspection": self.queue_limits[1],
            },
            "queue_full_rejections": {
                "general": inner.queue_full_rejections[0],
                "inspection": inner.queue_full_rejections[1],
            },
            "queue_scope": "execution-slot waiters only; excludes login and session waits",
            "peak_active": inner.peak_active,
        })
    }
}

#[derive(Debug)]
pub enum SlotWait {
    Full(QueueFull),
    Timeout(QueueTimeout),
}

/// Evidence for a per-target queue refusal, copied from finished result metadata.
pub fn queue_rejection(
    metadata: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    if metadata.get("reason").and_then(Value::as_str) != Some("queue_full") {
        return out;
    }
    for key in [
        "reason",
        "retryable",
        "queue",
        "executed",
        "execution_state",
        "completion_unknown",
        "queue_timed_out",
        "failure_stage",
    ] {
        if let Some(value) = metadata.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timings() -> Timings {
        Timings::default()
    }

    #[tokio::test]
    async fn grants_up_to_limit_and_rejects_beyond_queue() {
        let slots = ExecutionSlots::new(2, 0, 1, 0).unwrap();
        let mut t = timings();
        let a = slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t)
            .await
            .unwrap();
        let b = slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t)
            .await
            .unwrap();
        // Queue capacity is 1: a third caller fills the queue, a fourth is refused.
        let waiting = {
            let slots = slots.clone();
            tokio::spawn(async move {
                let mut t = Timings::default();
                slots
                    .acquire(Lane::General, Duration::from_millis(2000), &mut t)
                    .await
                    .map(|_| ())
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut t2 = timings();
        match slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t2)
            .await
        {
            Err(SlotWait::Full(full)) => assert_eq!(full.depth, 1),
            other => panic!("expected queue full, got {:?}", other.map(|_| ())),
        }
        drop(a);
        assert!(waiting.await.unwrap().is_ok());
        drop(b);
    }

    #[tokio::test]
    async fn general_lane_cannot_consume_the_inspection_reserve() {
        let slots = ExecutionSlots::new(2, 1, 4, 4).unwrap();
        let mut t = timings();
        let general = slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t)
            .await
            .unwrap();
        let blocked = {
            let slots = slots.clone();
            tokio::spawn(async move {
                let mut t = Timings::default();
                slots
                    .acquire(Lane::General, Duration::from_millis(80), &mut t)
                    .await
                    .map(|_| ())
            })
        };
        let mut t2 = Timings::default();
        // Inspection still fits while the reserve is idle.
        let inspection = slots
            .acquire(Lane::Inspection, Duration::from_millis(10), &mut t2)
            .await
            .unwrap();
        assert!(matches!(blocked.await.unwrap(), Err(SlotWait::Timeout(_))));
        drop(inspection);
        drop(general);
    }

    #[tokio::test]
    async fn queue_timeout_reports_the_queue_stage() {
        let slots = ExecutionSlots::new(1, 0, 4, 4).unwrap();
        let mut t = timings();
        let held = slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t)
            .await
            .unwrap();
        let mut t2 = Timings::default();
        match slots
            .acquire(Lane::General, Duration::from_millis(30), &mut t2)
            .await
        {
            Err(SlotWait::Timeout(timeout)) => assert_eq!(timeout.stage, "execution_queue"),
            other => panic!("expected timeout, got {:?}", other.map(|_| ())),
        }
        assert!(t2.queue_seconds >= 0.02);
        drop(held);
    }

    #[tokio::test]
    async fn status_reports_active_and_queued_counts() {
        let slots = ExecutionSlots::new(3, 1, 8, 8).unwrap();
        let mut t = timings();
        let guard = slots
            .acquire(Lane::General, Duration::from_millis(10), &mut t)
            .await
            .unwrap();
        let status = slots.status().await;
        assert_eq!(status["active"]["general"], 1);
        assert_eq!(status["general_limit"], 2);
        assert_eq!(status["queued"]["inspection"], 0);
        drop(guard);
        // Release is handed to the pump task, so allow it to run.
        for _ in 0..50 {
            if slots.status().await["active"]["general"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(slots.status().await["active"]["general"], 0);
    }
}
