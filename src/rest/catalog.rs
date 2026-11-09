//! An atomic, hourly snapshot of permitted REST assets.
//!
//! A snapshot is published only when it is complete. A failed refresh keeps the last
//! complete view, a cache is bound to the credential identity that produced it, and
//! an ambiguous account is never guessed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::task::JoinSet;

use crate::config::{BastionConfig, BridgeSettings};
use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::{asset_metadata, normalize_uuid, Host, Inventory};
use crate::rest::api::ApiClient;
use crate::storage::results::{atomic_json, now};

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub refreshed_at: f64,
    pub assets: Vec<Value>,
    pub identity: String,
}

impl Snapshot {
    fn to_json(&self) -> Value {
        json!({
            "refreshed_at": self.refreshed_at,
            "assets": self.assets,
            "identity": self.identity,
        })
    }

    fn from_json(value: &Value, identity: &str) -> Option<Self> {
        let map = value.as_object()?;
        if map.get("identity").and_then(Value::as_str) != Some(identity) {
            return None;
        }
        Some(Self {
            refreshed_at: map
                .get("refreshed_at")
                .and_then(Value::as_f64)
                .unwrap_or(0.0),
            assets: map
                .get("assets")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            identity: identity.to_string(),
        })
    }
}

struct CatalogState {
    snapshot: Snapshot,
    inventory: Inventory,
    error: Option<String>,
}

pub struct AssetCatalog {
    cfg: Arc<BastionConfig>,
    settings: Arc<BridgeSettings>,
    identity: String,
    cache: std::path::PathBuf,
    state: Mutex<CatalogState>,
    refresh_lock: AsyncMutex<()>,
    last_attempt: Mutex<f64>,
    closing: AtomicBool,
}

impl AssetCatalog {
    pub fn new(cfg: Arc<BastionConfig>, settings: Arc<BridgeSettings>) -> BridgeResult<Arc<Self>> {
        let state_dir = settings.state_dir.clone();
        std::fs::create_dir_all(&state_dir)?;
        let mut identity_parts: Vec<Option<String>> = cfg.credential_identity();
        identity_parts.push(settings.preferred_account.clone());
        let identity = hex::encode(Sha256::digest(
            serde_json::to_vec(&identity_parts)?.as_slice(),
        ));
        let cache = state_dir.join("assets.json");
        let mut state = CatalogState {
            snapshot: Snapshot {
                refreshed_at: 0.0,
                assets: Vec::new(),
                identity: identity.clone(),
            },
            inventory: Inventory::default(),
            error: None,
        };
        if let Ok(text) = std::fs::read_to_string(&cache) {
            match serde_json::from_str::<Value>(&text) {
                Ok(value) => match Snapshot::from_json(&value, &identity) {
                    Some(snapshot) => {
                        state.inventory = build_inventory(&snapshot, &settings, &cfg);
                        state.snapshot = snapshot;
                    }
                    None => state.error = Some("cached asset snapshot is invalid".into()),
                },
                Err(_) => state.error = Some("cached asset snapshot is invalid".into()),
            }
        }
        Ok(Arc::new(Self {
            cfg,
            settings,
            identity,
            cache,
            state: Mutex::new(state),
            refresh_lock: AsyncMutex::new(()),
            last_attempt: Mutex::new(0.0),
            closing: AtomicBool::new(false),
        }))
    }

    pub fn config(&self) -> &Arc<BastionConfig> {
        &self.cfg
    }

    pub fn settings(&self) -> &Arc<BridgeSettings> {
        &self.settings
    }

    pub fn make_api(&self) -> BridgeResult<ApiClient> {
        ApiClient::new((*self.cfg).clone(), self.settings.rest_proxy.as_deref())
    }

    pub fn snapshot_assets(&self) -> Vec<Value> {
        self.state
            .lock()
            .expect("catalog lock")
            .snapshot
            .assets
            .clone()
    }

    /// Unique address per asset id (and per unique display name) for compact views.
    pub fn addresses(&self) -> std::collections::HashMap<String, String> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let assets = self.snapshot_assets();
        for asset in &assets {
            if let Some(address) = asset.get("address").and_then(Value::as_str) {
                *counts.entry(address.to_string()).or_insert(0) += 1;
            }
        }
        let mut out = std::collections::HashMap::new();
        for asset in &assets {
            let Some(address) = asset.get("address").and_then(Value::as_str) else {
                continue;
            };
            if counts.get(address).copied() != Some(1) {
                continue;
            }
            if let Some(name) = asset.get("name").and_then(Value::as_str) {
                out.insert(name.to_string(), address.to_string());
            }
            if let Some(id) = asset.get("id").and_then(Value::as_str) {
                out.insert(format!("asset-{id}"), address.to_string());
                out.insert(id.to_string(), address.to_string());
            }
        }
        out
    }

    pub fn inventory(&self) -> Inventory {
        self.state.lock().expect("catalog lock").inventory.clone()
    }

    pub fn status(&self) -> Value {
        let state = self.state.lock().expect("catalog lock");
        let refreshed = state.snapshot.refreshed_at;
        let warnings = &state.inventory.metadata_warnings;
        let stale = refreshed <= 0.0 || now() - refreshed >= self.settings.refresh_interval as f64;
        let mut out = json!({
            "source": "JumpServer REST",
            "refresh_interval_seconds": self.settings.refresh_interval,
            "last_success": if refreshed > 0.0 { json!(refreshed) } else { Value::Null },
            "next_refresh": if refreshed > 0.0 {
                json!(refreshed + self.settings.refresh_interval as f64)
            } else {
                Value::Null
            },
            "stale": stale,
            "assets": state.snapshot.assets.len(),
            "ssh_targets": state.inventory.hosts.len(),
            "last_error": state.error.clone().map(Value::from).unwrap_or(Value::Null),
            "refresh_in_progress": false,
        });
        if !warnings.is_empty() {
            let map = out.as_object_mut().expect("object");
            map.insert(
                "metadata_warnings".into(),
                Value::Array(
                    warnings
                        .iter()
                        .take(5)
                        .map(|warning| Value::from(warning.clone()))
                        .collect(),
                ),
            );
            map.insert("metadata_warning_count".into(), json!(warnings.len()));
            map.insert(
                "metadata_warnings_truncated".into(),
                Value::Bool(warnings.len() > 5),
            );
        }
        out
    }

    /// Why the snapshot has assets but no usable SSH target.
    pub fn explain_no_targets(&self) -> Option<String> {
        let state = self.state.lock().expect("catalog lock");
        if !state.inventory.hosts.is_empty() || state.snapshot.assets.is_empty() {
            return None;
        }
        let ssh: Vec<&Value> = state
            .snapshot
            .assets
            .iter()
            .filter(|asset| {
                asset
                    .get("active")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    && asset
                        .get("protocols")
                        .and_then(Value::as_array)
                        .map(|protocols| protocols.iter().any(|value| value == "ssh"))
                        .unwrap_or(false)
            })
            .collect();
        if ssh.is_empty() {
            return Some(format!(
                "{} assets are visible, but none is active with an SSH protocol permitted; check the asset/protocol permissions.",
                state.snapshot.assets.len()
            ));
        }
        let all_unresolved = ssh
            .iter()
            .all(|asset| asset.get("account").map(Value::is_null).unwrap_or(true));
        if !all_unresolved {
            return None;
        }
        let hint = match &self.settings.preferred_account {
            None => "set bridge.preferred_account in config.toml to one the assets permit (for example \"root\")".to_string(),
            Some(account) => format!(
                "bridge.preferred_account is {account:?}, which none of these assets permits"
            ),
        };
        let mut offered: Vec<usize> = ssh
            .iter()
            .filter_map(|asset| asset.get("accounts").and_then(Value::as_array))
            .map(|accounts| {
                accounts
                    .iter()
                    .filter(|value| value.as_str().is_some())
                    .count()
            })
            .collect();
        offered.sort_unstable();
        offered.dedup();
        let plural = offered
            .first()
            .map(|count| format!(" (typically {count})"))
            .unwrap_or_default();
        Some(format!(
            "{} active SSH assets are visible, but every one offers several permitted accounts{} and no account is selected, so none becomes a target: {hint}.",
            ssh.len(),
            plural
        ))
    }

    pub fn search(&self, query: &str, offset: usize, limit: usize) -> Value {
        let state = self.state.lock().expect("catalog lock");
        let needle = query.to_lowercase();
        let rows: Vec<&Value> = state
            .snapshot
            .assets
            .iter()
            .filter(|asset| {
                if needle.is_empty() {
                    return true;
                }
                let haystack = format!(
                    "{} {} {}",
                    asset.get("name").and_then(Value::as_str).unwrap_or(""),
                    asset.get("id").and_then(Value::as_str).unwrap_or(""),
                    asset.get("address").and_then(Value::as_str).unwrap_or("")
                );
                haystack.to_lowercase().contains(&needle)
            })
            .collect();
        let page: Vec<Value> = rows
            .iter()
            .skip(offset)
            .take(limit)
            .map(|asset| {
                let why = exclusion(asset);
                let mut row = Map::new();
                for key in ["id", "name", "address", "active", "protocols"] {
                    if let Some(value) = asset.get(key) {
                        row.insert(key.to_string(), value.clone());
                    }
                }
                row.insert("usable".into(), Value::Bool(why.is_none()));
                row.insert(
                    "accounts".into(),
                    asset.get("accounts").cloned().unwrap_or(json!([])),
                );
                row.insert(
                    "account".into(),
                    asset.get("account").cloned().unwrap_or(Value::Null),
                );
                if let Some(why) = why {
                    row.insert("unusable_because".into(), Value::from(why));
                }
                Value::Object(row)
            })
            .collect();
        let matched = rows.len();
        let mut out = Map::new();
        out.insert("assets".into(), Value::Array(page));
        out.insert("matched".into(), json!(matched));
        out.insert(
            "next_offset".into(),
            if offset + out["assets"].as_array().map(Vec::len).unwrap_or(0) < matched {
                json!(offset + out["assets"].as_array().map(Vec::len).unwrap_or(0))
            } else {
                Value::Null
            },
        );
        drop(state);
        out.insert("inventory".into(), self.status());
        Value::Object(out)
    }

    /// Fetch, build, persist, then publish — in that order.
    pub async fn refresh(&self) -> Value {
        let _guard = self.refresh_lock.lock().await;
        *self.last_attempt.lock().expect("attempt lock") = now();
        let mut stage = "API fetch";
        let mut hint = "check API access/configuration";
        let result = async {
            let assets = self.fetch_assets().await?;
            stage = "snapshot preparation";
            hint = "check snapshot data and local state storage";
            let snapshot = Snapshot {
                refreshed_at: now(),
                assets,
                identity: self.identity.clone(),
            };
            let inventory = build_inventory(&snapshot, &self.settings, &self.cfg);
            atomic_json(&self.cache, &snapshot.to_json())?;
            Ok::<_, BridgeError>((snapshot, inventory))
        }
        .await;
        match result {
            Ok((snapshot, inventory)) => {
                let mut state = self.state.lock().expect("catalog lock");
                state.snapshot = snapshot;
                state.inventory = inventory;
                state.error = None;
                drop(state);
                let status = self.status();
                tracing::info!(
                    assets = status["assets"].as_u64().unwrap_or(0),
                    ssh_targets = status["ssh_targets"].as_u64().unwrap_or(0),
                    "REST refresh complete"
                );
            }
            Err(error) => {
                // Never publish raw HTTP bodies, proxy URLs, or authentication material.
                let message = format!(
                    "REST refresh failed during {stage} ({}); {hint}",
                    error_kind(&error)
                );
                tracing::warn!(%message, "previous snapshot retained");
                self.state.lock().expect("catalog lock").error = Some(message);
            }
        }
        let mut status = self.status();
        if let Some(map) = status.as_object_mut() {
            map.insert(
                "ok".into(),
                Value::Bool(map.get("last_error").map(Value::is_null).unwrap_or(true)),
            );
            map.insert("refresh_in_progress".into(), Value::Bool(false));
        }
        status
    }

    async fn fetch_assets(&self) -> BridgeResult<Vec<Value>> {
        let api = self.make_api()?;
        let (assets, truncated) = api.list_assets(None, 200, 100).await?;
        if truncated {
            return Err(BridgeError::rest("REST returned a partial asset list"));
        }
        let semaphore = Arc::new(Semaphore::new(4));
        let mut set: JoinSet<DetailOutcome> = JoinSet::new();
        let preferred = self.settings.preferred_account.clone();
        let login = self.cfg.login_user.clone();
        for asset in assets {
            let api_cfg = (*self.cfg).clone();
            let proxy = self.settings.rest_proxy.clone();
            let preferred = preferred.clone();
            let login = login.clone();
            let permit = semaphore.clone();
            let Some(id) = asset.get("id").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            set.spawn(async move {
                let _permit = match permit.acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => return DetailOutcome::Failed("detail semaphore closed".into()),
                };
                let api = match ApiClient::new(api_cfg, proxy.as_deref()) {
                    Ok(api) => api,
                    Err(error) => return DetailOutcome::Failed(error.message().to_string()),
                };
                match api.get_asset(&id).await {
                    Ok(data) => DetailOutcome::Row(asset_row(&data, &preferred, &login)),
                    // Only an explicit permission answer removes an asset; a timeout or
                    // server error must not silently shrink the snapshot.
                    Err(error) if permission_denied(&error) => DetailOutcome::Gone,
                    Err(error) => DetailOutcome::Failed(error.message().to_string()),
                }
            });
        }
        let mut rows = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(DetailOutcome::Row(row)) => rows.push(row),
                Ok(DetailOutcome::Gone) => {}
                Ok(DetailOutcome::Failed(message)) => failures.push(message),
                Err(error) => {
                    return Err(BridgeError::rest(format!(
                        "asset detail task failed: {error}"
                    )))
                }
            }
        }
        if let Some(first) = failures.first() {
            // Keep the previous complete snapshot instead of publishing a partial one.
            return Err(BridgeError::rest(format!(
                "{} asset detail request(s) failed (first: {first}); refusing a partial snapshot",
                failures.len()
            )));
        }
        Ok(rows)
    }

    /// Ensure a complete snapshot exists, refreshing when stale.
    pub async fn ensure(&self) -> BridgeResult<Inventory> {
        let refreshed = self
            .state
            .lock()
            .expect("catalog lock")
            .snapshot
            .refreshed_at;
        let locked = self.refresh_lock.try_lock().is_err();
        if refreshed > 0.0 && locked {
            // Keep the last complete view usable while another request refreshes.
            return Ok(self.inventory());
        }
        if refreshed <= 0.0 && locked {
            let _guard = self.refresh_lock.lock().await;
        }
        if now() - refreshed >= self.settings.refresh_interval as f64 {
            let last = *self.last_attempt.lock().expect("attempt lock");
            if now() - last > 5.0 {
                self.refresh().await;
            }
        }
        let state = self.state.lock().expect("catalog lock");
        if state.snapshot.refreshed_at <= 0.0 {
            return Err(BridgeError::inventory(state.error.clone().unwrap_or_else(
                || "REST inventory is not ready; configure API access first".into(),
            )));
        }
        Ok(state.inventory.clone())
    }

    /// One REST health call for `doctor`; never touches the cached snapshot.
    pub async fn probe_health(
        &self,
        timeout: std::time::Duration,
    ) -> crate::errors::BridgeResult<Value> {
        let api = self.make_api()?;
        tokio::time::timeout(timeout, api.health())
            .await
            .map_err(|_| crate::errors::BridgeError::rest("health check timed out"))?
    }

    /// Bastion version from the public settings endpoint; `None` when unauthenticated
    /// deployments hide it.
    pub async fn probe_version(
        &self,
        timeout: std::time::Duration,
    ) -> crate::errors::BridgeResult<Option<String>> {
        let api = self.make_api()?;
        tokio::time::timeout(timeout, api.version())
            .await
            .map_err(|_| crate::errors::BridgeError::rest("version check timed out"))
    }

    pub fn start(self: &Arc<Self>) {
        let catalog = self.clone();
        tokio::spawn(async move {
            // REST unavailability must not prevent MCP initialization or status calls.
            catalog.refresh().await;
            loop {
                if catalog.closing.load(Ordering::SeqCst) {
                    return;
                }
                let sleep_for = catalog.settings.refresh_interval.min(30) as f64;
                tokio::time::sleep(std::time::Duration::from_secs_f64(sleep_for.max(0.2))).await;
                if catalog.closing.load(Ordering::SeqCst) {
                    return;
                }
                let refreshed = catalog
                    .state
                    .lock()
                    .expect("catalog lock")
                    .snapshot
                    .refreshed_at;
                let has_error = catalog.state.lock().expect("catalog lock").error.is_some();
                let due = now() - refreshed >= catalog.settings.refresh_interval as f64;
                let retry_after = catalog.settings.refresh_interval.min(300) as f64;
                let last = *catalog.last_attempt.lock().expect("attempt lock");
                if (due || has_error) && now() - last >= retry_after {
                    catalog.refresh().await;
                }
            }
        });
    }

    pub fn close(&self) {
        self.closing.store(true, Ordering::SeqCst);
    }
}

/// Result of one per-asset detail request during a snapshot refresh.
enum DetailOutcome {
    Row(Value),
    /// The API explicitly answered that this asset is no longer permitted.
    Gone,
    Failed(String),
}

fn permission_denied(error: &BridgeError) -> bool {
    let message = error.message();
    message.contains(" -> 403:") || message.contains(" -> 404:")
}

fn error_kind(error: &BridgeError) -> &'static str {
    match error {
        BridgeError::Invalid(_) => "ValueError",
        BridgeError::Config(_) => "ConfigError",
        BridgeError::Inventory(_) => "InventoryError",
        BridgeError::Rest(_) => "JumpServerError",
        BridgeError::Storage(_) => "OSError",
        BridgeError::Ssh(_) => "SshError",
    }
}

fn asset_row(data: &Value, preferred: &Option<String>, login: &Option<String>) -> Value {
    let mut usable: Vec<String> = Vec::new();
    if let Some(accounts) = data.get("permed_accounts").and_then(Value::as_array) {
        for account in accounts {
            let has_secret = account
                .get("has_secret")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !has_secret {
                continue;
            }
            let Some(username) = account.get("username").and_then(Value::as_str) else {
                continue;
            };
            if !usable.iter().any(|existing| existing == username) {
                usable.push(username.to_string());
            }
        }
    }
    // Exactly one permitted account, or the one explicitly configured. Several
    // equally plausible accounts stay unresolved: the bridge never picks an
    // identity on the caller's behalf, because file ownership and environment
    // differ per account.
    let account = match preferred {
        Some(preferred) => usable
            .iter()
            .find(|candidate| *candidate == preferred)
            .cloned(),
        None if usable.len() == 1 => usable.first().cloned(),
        None => None,
    };
    let protocols: Vec<String> = data
        .get("permed_protocols")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let id = data
        .get("id")
        .and_then(Value::as_str)
        .and_then(normalize_uuid)
        .unwrap_or_else(|| {
            data.get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        });
    json!({
        "id": id,
        "name": data.get("name").and_then(Value::as_str).unwrap_or(""),
        "address": data.get("address").and_then(Value::as_str).unwrap_or(""),
        "active": data.get("is_active").and_then(Value::as_bool).unwrap_or(true),
        "protocols": protocols,
        "accounts": usable,
        "account": account.map(Value::from).unwrap_or(Value::Null),
        "login": login.clone().map(Value::from).unwrap_or(Value::Null),
    })
}

/// Why this asset is not a usable target, or `None` when it is one.
pub fn exclusion(asset: &Value) -> Option<String> {
    if !asset
        .get("active")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Some("is inactive in JumpServer, so it is not a target".into());
    }
    let protocols: Vec<&str> = asset
        .get("protocols")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !protocols.contains(&"ssh") {
        let listed = if protocols.is_empty() {
            "none".to_string()
        } else {
            protocols.join(", ")
        };
        return Some(format!("permits no ssh protocol (has: {listed})"));
    }
    let account = asset.get("account").and_then(Value::as_str);
    let Some(account) = account else {
        return Some("has no unambiguous account selected (see bridge.preferred_account)".into());
    };
    let login = asset.get("login").and_then(Value::as_str).unwrap_or("");
    if login.is_empty() || !login_allowed(login) {
        return Some(format!("has an unusable login {login:?}"));
    }
    if !account_allowed(account) {
        return Some(format!("has an unusable account name {account:?}"));
    }
    None
}

fn login_allowed(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-'))
}

fn account_allowed(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn build_inventory(
    snapshot: &Snapshot,
    settings: &BridgeSettings,
    cfg: &BastionConfig,
) -> Inventory {
    let mut warnings = Vec::new();
    let metadata = match asset_metadata(None, &mut warnings) {
        Ok(metadata) => metadata,
        Err(_) => BTreeMap::new(),
    };
    let mut name_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut address_counts: BTreeMap<String, usize> = BTreeMap::new();
    for asset in &snapshot.assets {
        if let Some(name) = asset.get("name").and_then(Value::as_str) {
            *name_counts.entry(name.to_string()).or_insert(0) += 1;
        }
        if let Some(address) = asset.get("address").and_then(Value::as_str) {
            *address_counts.entry(address.to_string()).or_insert(0) += 1;
        }
    }
    let mut hosts: Vec<Host> = Vec::new();
    let mut selectors: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut excluded: BTreeMap<String, String> = BTreeMap::new();
    for asset in &snapshot.assets {
        let Some(raw_id) = asset.get("id").and_then(Value::as_str) else {
            continue;
        };
        let asset_id = normalize_uuid(raw_id).unwrap_or_else(|| raw_id.to_string());
        let name = asset.get("name").and_then(Value::as_str).unwrap_or("");
        if let Some(reason) = exclusion(asset) {
            let label = format!("'{name}' {reason}");
            for key in [name, asset_id.as_str()] {
                if !key.is_empty() {
                    excluded.entry(key.to_string()).or_insert(label.clone());
                }
            }
            continue;
        }
        let overlay = metadata.get(&asset_id).cloned().unwrap_or_default();
        let address = asset
            .get("address")
            .and_then(Value::as_str)
            .map(str::to_string);
        // A readable name is the target identity; duplicate or reserved names fall
        // back to a stable `asset-<uuid>` so a selector never fans out by accident.
        let display_name = if !name.is_empty()
            && name != "all"
            && name != "*"
            && name_counts.get(name).copied() == Some(1)
        {
            name.to_string()
        } else {
            format!("asset-{asset_id}")
        };
        let host = Host {
            name: display_name.clone(),
            login: asset
                .get("login")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| cfg.login_user.clone()),
            account: asset
                .get("account")
                .and_then(Value::as_str)
                .map(str::to_string),
            asset_id: Some(asset_id.clone()),
            address: address.clone(),
            platform: overlay
                .platform
                .clone()
                .unwrap_or_else(|| "generic".to_string()),
            env_setup: overlay.env_setup.clone(),
            workdir: overlay.workdir.clone(),
            tags: Vec::new(),
        };
        hosts.push(host);
        for (label, unique) in [
            (display_name.clone(), true),
            (format!("jms-{asset_id}"), true),
            (asset_id.clone(), true),
            (
                address.clone().unwrap_or_default(),
                address
                    .as_ref()
                    .map(|value| address_counts.get(value).copied() == Some(1))
                    .unwrap_or(false),
            ),
        ] {
            if !label.is_empty() && label != "all" && label != "*" && unique {
                selectors
                    .entry(label)
                    .or_default()
                    .push(display_name.clone());
            }
        }
    }
    let host_names: Vec<String> = hosts.iter().map(|host| host.name.clone()).collect();
    let groups: BTreeMap<String, Vec<String>> = selectors
        .into_iter()
        .filter_map(|(label, mut members)| {
            members.sort();
            members.dedup();
            if members.len() == 1 && !host_names.contains(&label) {
                Some((label, members))
            } else {
                None
            }
        })
        .collect();
    let _ = settings;
    Inventory {
        hosts,
        groups,
        excluded,
        metadata_warnings: warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asset(
        id: &str,
        name: &str,
        address: &str,
        accounts: Vec<&str>,
        account: Option<&str>,
    ) -> Value {
        json!({
            "id": id, "name": name, "address": address, "active": true,
            "protocols": ["ssh", "sftp"], "accounts": accounts, "account": account,
            "login": "yjwu",
        })
    }

    fn snapshot(assets: Vec<Value>) -> Snapshot {
        Snapshot {
            refreshed_at: 1.0,
            assets,
            identity: "id".into(),
        }
    }

    #[test]
    fn only_ssh_active_assets_with_one_account_become_targets() {
        let snapshot = snapshot(vec![
            asset(
                "11111111-1111-1111-1111-111111111111",
                "a",
                "10.0.0.1",
                vec!["root"],
                Some("root"),
            ),
            asset(
                "22222222-2222-2222-2222-222222222222",
                "b",
                "10.0.0.2",
                vec!["root", "ops"],
                None,
            ),
        ]);
        let inventory = build_inventory(
            &snapshot,
            &BridgeSettings::default(),
            &BastionConfig::default(),
        );
        assert_eq!(inventory.hosts.len(), 1);
        assert_eq!(inventory.hosts[0].name, "a");
        assert_eq!(inventory.hosts[0].account.as_deref(), Some("root"));
        assert!(inventory
            .excluded
            .get("b")
            .unwrap()
            .contains("no unambiguous account"));
        // The display name, the asset id and the managed alias all resolve to one host.
        for selector in [
            "a",
            "11111111-1111-1111-1111-111111111111",
            "jms-11111111-1111-1111-1111-111111111111",
        ] {
            let hosts = inventory.resolve(&[selector.to_string()]).unwrap();
            assert_eq!(hosts.len(), 1, "{selector}");
            assert_eq!(hosts[0].name, "a");
        }
    }

    #[test]
    fn exclusion_reasons_name_the_real_cause() {
        let inactive = json!({"id": "i", "name": "n", "address": "x", "active": false,
                              "protocols": ["ssh"], "accounts": ["root"], "account": "root"});
        assert_eq!(
            exclusion(&inactive).unwrap(),
            "is inactive in JumpServer, so it is not a target"
        );
        let no_ssh = json!({"id": "i", "name": "n", "address": "x", "active": true,
                            "protocols": ["rdp"], "accounts": ["root"], "account": "root"});
        assert_eq!(
            exclusion(&no_ssh).unwrap(),
            "permits no ssh protocol (has: rdp)"
        );
        let none = json!({"id": "i", "name": "n", "address": "x", "active": true,
                          "protocols": [], "accounts": [], "account": "root"});
        assert!(exclusion(&none).unwrap().contains("has: none"));
        let bad_login = json!({"id": "i", "name": "n", "address": "x", "active": true,
                               "protocols": ["ssh"], "accounts": ["root"], "account": "root",
                               "login": "bad login"});
        assert!(exclusion(&bad_login).unwrap().contains("unusable login"));
    }

    #[test]
    fn duplicate_display_names_are_not_selectors() {
        let snapshot = snapshot(vec![
            asset(
                "11111111-1111-1111-1111-111111111111",
                "dup",
                "10.0.0.1",
                vec!["root"],
                Some("root"),
            ),
            asset(
                "22222222-2222-2222-2222-222222222222",
                "dup",
                "10.0.0.2",
                vec!["root"],
                Some("root"),
            ),
        ]);
        let inventory = build_inventory(
            &snapshot,
            &BridgeSettings::default(),
            &BastionConfig::default(),
        );
        assert_eq!(inventory.hosts.len(), 2);
        assert!(!inventory.groups.contains_key("dup"));
        assert!(inventory.resolve(&["dup".to_string()]).is_err());
    }

    #[test]
    fn ambiguous_address_is_not_mapped_to_a_single_host() {
        let catalog = |assets: Vec<Value>| -> Vec<Value> { assets };
        let _ = catalog;
        let addresses_source = vec![
            asset(
                "11111111-1111-1111-1111-111111111111",
                "a",
                "10.0.0.1",
                vec!["root"],
                Some("root"),
            ),
            asset(
                "22222222-2222-2222-2222-222222222222",
                "b",
                "10.0.0.1",
                vec!["root"],
                Some("root"),
            ),
        ];
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for asset in &addresses_source {
            *counts
                .entry(asset["address"].as_str().unwrap().to_string())
                .or_insert(0) += 1;
        }
        assert_eq!(counts["10.0.0.1"], 2);
    }

    #[test]
    fn account_resolution_follows_preferred_then_uniqueness() {
        let row = asset_row(
            &json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "a", "address": "10.0.0.1", "is_active": true,
                "permed_accounts": [
                    {"username": "root", "has_secret": true},
                    {"username": "ops", "has_secret": true},
                    {"username": "nokey", "has_secret": false}
                ],
                "permed_protocols": [{"name": "ssh"}],
            }),
            &Some("ops".to_string()),
            &Some("yjwu".to_string()),
        );
        assert_eq!(row["account"], "ops");
        assert_eq!(row["accounts"], json!(["root", "ops"]));
        // Two permitted accounts stay unresolved until the operator configures one:
        // the bridge never decides an identity on the caller's behalf.
        let root_unresolved = asset_row(
            &json!({
                "id": "11111111-1111-1111-1111-111111111111", "name": "a",
                "permed_accounts": [
                    {"username": "root", "has_secret": true},
                    {"username": "ops", "has_secret": true}
                ],
            }),
            &None,
            &None,
        );
        assert_eq!(root_unresolved["account"], Value::Null);
        // Two non-root accounts stay unresolved: an identity is never guessed.
        let ambiguous = asset_row(
            &json!({
                "id": "11111111-1111-1111-1111-111111111111", "name": "a",
                "permed_accounts": [
                    {"username": "ops", "has_secret": true},
                    {"username": "svc", "has_secret": true}
                ],
            }),
            &None,
            &None,
        );
        assert_eq!(ambiguous["account"], Value::Null);
    }

    #[test]
    fn snapshot_cache_is_bound_to_credential_identity() {
        let snapshot = snapshot(vec![asset(
            "11111111-1111-1111-1111-111111111111",
            "a",
            "10.0.0.1",
            vec!["root"],
            Some("root"),
        )]);
        let value = snapshot.to_json();
        assert!(Snapshot::from_json(&value, "id").is_some());
        assert!(Snapshot::from_json(&value, "other").is_none());
    }
}
