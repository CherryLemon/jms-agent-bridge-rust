//! Host inventory: the logical view of the fleet.
//!
//! Reachability comes from the REST snapshot. `hosts.yaml` is now only an optional
//! per-asset metadata overlay (env_setup, workdir, platform), joined by asset UUID;
//! it never decides which assets exist.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::errors::{BridgeError, BridgeResult};

/// Platform profile keys accepted by `hosts.yaml`. Unknown keys are ignored with a
/// warning rather than silently probing the wrong vendor tool.
pub const PLATFORMS: [&str; 20] = [
    "ascend-910c",
    "ascend",
    "cuda",
    "nvidia",
    "aarch64",
    "arm64",
    "generic",
    "hygon-dcu",
    "hygon",
    "metax",
    "enflame",
    "kunlunxin",
    "kunlun",
    "thead",
    "t-head",
    "iluvatar",
    "moore-threads",
    "mthreads",
    "tsingmicro",
    "tsm",
];

pub fn platform_supported(key: &str) -> bool {
    PLATFORMS.contains(&key)
}

/// Single-quote a value for safe interpolation into a POSIX shell snippet.
pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Build the remote bash script piped into `bash -s`.
pub fn wrap_command(env_setup: Option<&str>, workdir: Option<&str>, command: &str) -> String {
    let mut lines = vec!["set -euo pipefail".to_string()];
    if let Some(env_setup) = env_setup.filter(|value| !value.is_empty()) {
        // Vendor env scripts reference variables that may be unset.
        lines.push("set +u".into());
        lines.push(env_setup.to_string());
        lines.push("set -u".into());
    }
    if let Some(workdir) = workdir.filter(|value| !value.is_empty()) {
        lines.push(format!(
            "mkdir -p {quoted} && cd {quoted}",
            quoted = shell_quote(workdir)
        ));
    }
    lines.push(command.to_string());
    lines.join("\n") + "\n"
}

#[derive(Debug, Clone, Default)]
pub struct Host {
    /// Asset UUID for REST targets; friendly name for legacy YAML targets.
    pub name: String,
    pub login: Option<String>,
    pub account: Option<String>,
    pub asset_id: Option<String>,
    /// The asset's own address as JumpServer knows it.
    pub address: Option<String>,
    pub platform: String,
    pub env_setup: Option<String>,
    pub workdir: Option<String>,
    pub tags: Vec<String>,
}

impl Host {
    /// The JumpServer per-asset SSH login: `login#account#asset_id`.
    pub fn login_string(&self, default_login: Option<&str>) -> BridgeResult<String> {
        let login = self.login.as_deref().or(default_login).ok_or_else(|| {
            BridgeError::inventory(format!(
                "host {:?} has no 'login' and no default login user is configured",
                self.name
            ))
        })?;
        let mut pieces = vec![login.to_string()];
        if let Some(account) = &self.account {
            pieces.push(account.clone());
        }
        if let Some(asset_id) = &self.asset_id {
            pieces.push(asset_id.clone());
        }
        Ok(pieces.join("#"))
    }

    /// Identity of the SSH session: login, account and asset UUID all matter.
    pub fn connection_key(&self) -> BridgeResult<String> {
        let (Some(asset_id), Some(account), Some(login)) =
            (&self.asset_id, &self.account, &self.login)
        else {
            return Err(BridgeError::config(
                "target needs a permitted REST asset ID and account",
            ));
        };
        Ok(format!("{login}\u{1f}{account}\u{1f}{asset_id}"))
    }
}

#[derive(Debug, Default, Clone)]
pub struct Inventory {
    pub hosts: Vec<Host>,
    /// Unique names/addresses that resolve to exactly one asset id.
    pub groups: BTreeMap<String, Vec<String>>,
    pub excluded: BTreeMap<String, String>,
    pub metadata_warnings: Vec<String>,
}

impl Inventory {
    fn index(&self) -> HashMap<&str, &Host> {
        let mut map = HashMap::with_capacity(self.hosts.len());
        for host in &self.hosts {
            map.insert(host.name.as_str(), host);
        }
        map
    }

    /// Resolve names, unique aliases, groups, tags, or `all`/`*` into hosts.
    pub fn resolve(&self, selectors: &[String]) -> BridgeResult<Vec<Host>> {
        let by_name = self.index();
        let mut picked: Vec<Host> = Vec::new();
        let mut seen: HashMap<String, ()> = HashMap::new();
        let mut push = |host: &Host, picked: &mut Vec<Host>| {
            if seen.insert(host.name.clone(), ()).is_none() {
                picked.push(host.clone());
            }
        };
        for selector in selectors {
            match selector.as_str() {
                "all" | "*" => {
                    for host in &self.hosts {
                        push(host, &mut picked);
                    }
                }
                _ => {
                    if let Some(members) = self.groups.get(selector) {
                        for name in members {
                            match by_name.get(name.as_str()) {
                                Some(host) => push(host, &mut picked),
                                None => {
                                    return Err(BridgeError::inventory(format!(
                                        "group {selector:?} references unknown host {name:?}"
                                    )))
                                }
                            }
                        }
                    } else if let Some(host) = by_name.get(selector.as_str()) {
                        push(host, &mut picked);
                    } else {
                        let tagged: Vec<&Host> = self
                            .hosts
                            .iter()
                            .filter(|host| host.tags.iter().any(|tag| tag == selector))
                            .collect();
                        if tagged.is_empty() {
                            return Err(self.no_match(selector));
                        }
                        for host in tagged {
                            push(host, &mut picked);
                        }
                    }
                }
            }
        }
        Ok(picked)
    }

    /// Name the real cause of an empty match: an asset that is visible but unusable.
    pub fn no_match(&self, selector: &str) -> BridgeError {
        let reasons: Vec<&String> = self
            .excluded
            .iter()
            .filter(|(label, _)| label.as_str() == selector)
            .map(|(_, reason)| reason)
            .collect();
        if !reasons.is_empty() {
            let mut unique: Vec<String> = reasons.iter().map(|value| (*value).clone()).collect();
            unique.sort();
            unique.dedup();
            return BridgeError::inventory(format!(
                "target is in the REST snapshot but is not a usable target: {}",
                unique.join("; ")
            ));
        }
        BridgeError::inventory(
            "target is not in the REST snapshot; use discover(topic=\"assets\", query=...)",
        )
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

#[derive(Debug, Default, Clone)]
pub struct AssetOverlay {
    pub env_setup: Option<String>,
    pub workdir: Option<String>,
    pub platform: Option<String>,
}

pub fn inventory_path(explicit: Option<&Path>) -> BridgeResult<PathBuf> {
    if let Some(value) = std::env::var_os("JMS_BRIDGE_INVENTORY") {
        return Ok(PathBuf::from(value));
    }
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    Ok(home_dir()?.join(".config/jms-bridge/hosts.yaml"))
}

pub fn home_dir() -> BridgeResult<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| BridgeError::config("HOME is not set"))
}

/// Read the optional `hosts.yaml` metadata overlay keyed by REST asset UUID.
///
/// Missing files are normal for REST-only deployments. Invalid files or fields are
/// ignored with diagnostics; valid fields stay usable. Connection and authorization
/// fields are never copied, and no configuration value is echoed in a warning.
pub fn asset_metadata(
    path: Option<&Path>,
    warnings: &mut Vec<String>,
) -> BridgeResult<BTreeMap<String, AssetOverlay>> {
    let path = inventory_path(path)?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            warnings.push(format!(
                "hosts.yaml metadata could not be read ({}); overlay ignored",
                io_kind(&error)
            ));
            return Ok(BTreeMap::new());
        }
    };
    let document: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(value) => value,
        Err(error) => {
            warnings.push(format!(
                "hosts.yaml metadata could not be read ({}); overlay ignored",
                yaml_kind(&error)
            ));
            return Ok(BTreeMap::new());
        }
    };
    if document.is_null() {
        return Ok(BTreeMap::new());
    }
    let Some(hosts) = document.get("hosts") else {
        return Ok(BTreeMap::new());
    };
    let Some(hosts) = hosts.as_mapping() else {
        warnings.push("hosts.yaml hosts must be a mapping; metadata overlay ignored".into());
        return Ok(BTreeMap::new());
    };
    let mut metadata: BTreeMap<String, AssetOverlay> = BTreeMap::new();
    let mut seen: Vec<String> = Vec::new();
    for (index, (_key, spec)) in hosts.iter().enumerate() {
        let context = format!("hosts.yaml entry #{}", index + 1);
        if spec.is_null() {
            continue;
        }
        let Some(spec) = spec.as_mapping() else {
            warnings.push(format!("{context} must be a mapping; entry ignored"));
            continue;
        };
        let mut fields: BTreeMap<&str, &str> = BTreeMap::new();
        for name in ["env_setup", "workdir", "platform"] {
            if let Some(value) = spec.get(serde_yaml::Value::String(name.to_string())) {
                if !value.is_null() {
                    match value.as_str() {
                        Some(text) => {
                            fields.insert(name, text);
                        }
                        None => {
                            warnings.push(format!(
                                "{context}.{name} must be a string without NUL; field ignored"
                            ));
                        }
                    }
                }
            }
        }
        if fields.is_empty() {
            continue;
        }
        let asset_id = match spec
            .get(serde_yaml::Value::String("asset_id".into()))
            .and_then(|value| value.as_str())
            .and_then(normalize_uuid)
        {
            Some(asset_id) => asset_id,
            // Entries without a UUID are legacy alias records: they carry no overlay
            // metadata for a REST asset, so they are skipped without noise.
            None => continue,
        };
        if seen.contains(&asset_id) {
            metadata.remove(&asset_id);
            if !warnings
                .iter()
                .any(|warning| warning.contains("duplicate asset_id"))
            {
                warnings.push(format!(
                    "{context} has a duplicate asset_id; all metadata for this asset ignored"
                ));
            }
            continue;
        }
        seen.push(asset_id.clone());
        let mut overlay = AssetOverlay::default();
        for (name, value) in fields {
            if value.contains('\0') {
                warnings.push(format!(
                    "{context}.{name} must be a string without NUL; field ignored"
                ));
                continue;
            }
            match name {
                "env_setup" => overlay.env_setup = Some(value.to_string()),
                "workdir" => overlay.workdir = Some(value.to_string()),
                "platform" => {
                    if platform_supported(value) {
                        overlay.platform = Some(value.to_string());
                    } else {
                        warnings.push(format!(
                            "{context}.platform is not a supported platform key; field ignored"
                        ));
                    }
                }
                _ => {}
            }
        }
        metadata.insert(asset_id, overlay);
    }
    Ok(metadata)
}

fn io_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => "PermissionDenied",
        _ => "OSError",
    }
}

fn yaml_kind(_error: &serde_yaml::Error) -> &'static str {
    "YAMLError"
}

/// Canonical lowercase UUID form, matching `str(uuid.UUID(...))`.
pub fn normalize_uuid(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let hex: String = trimmed.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// Compact JSON helper used by inventory-related views.
pub fn host_row(host: &Host) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert("host".into(), Value::from(host.name.clone()));
    if let Some(address) = &host.address {
        row.insert("address".into(), Value::from(address.clone()));
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory() -> Inventory {
        let hosts = vec![
            Host {
                name: "id-1".into(),
                login: Some("yjwu".into()),
                account: Some("root".into()),
                asset_id: Some("id-1".into()),
                address: Some("10.0.0.1".into()),
                platform: "generic".into(),
                tags: vec!["gpu".into()],
                ..Default::default()
            },
            Host {
                name: "id-2".into(),
                login: Some("yjwu".into()),
                account: Some("root".into()),
                asset_id: Some("id-2".into()),
                address: Some("10.0.0.2".into()),
                platform: "generic".into(),
                tags: vec!["gpu".into(), "cpu".into()],
                ..Default::default()
            },
        ];
        let mut groups = BTreeMap::new();
        groups.insert("node-1".to_string(), vec!["id-1".to_string()]);
        Inventory {
            hosts,
            groups,
            excluded: BTreeMap::new(),
            metadata_warnings: Vec::new(),
        }
    }

    #[test]
    fn login_string_uses_three_hash_fields() {
        let inventory = inventory();
        assert_eq!(
            inventory.hosts[0].login_string(Some("fallback")).unwrap(),
            "yjwu#root#id-1"
        );
        let bare = Host {
            name: "x".into(),
            account: None,
            ..Default::default()
        };
        assert_eq!(bare.login_string(Some("yjwu")).unwrap(), "yjwu");
        assert!(bare.login_string(None).is_err());
    }

    #[test]
    fn resolve_dedupes_and_expands_aliases_tags_and_all() {
        let inventory = inventory();
        let picked = inventory
            .resolve(&["node-1".into(), "gpu".into(), "id-1".into()])
            .unwrap();
        assert_eq!(picked.len(), 2);
        let all = inventory.resolve(&["*".into()]).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn unknown_selector_explains_snapshot_not_membership() {
        let mut inventory = inventory();
        inventory.excluded.insert(
            "down-1".to_string(),
            "'down-1' is inactive in JumpServer, so it is not a target".to_string(),
        );
        let error = inventory.resolve(&["down-1".into()]).unwrap_err();
        assert!(error.message().contains("not a usable target"));
        let other = inventory.resolve(&["nope".into()]).unwrap_err();
        assert!(other.message().contains("not in the REST snapshot"));
    }

    #[test]
    fn wrap_command_relaxes_u_only_for_env_setup() {
        let script = wrap_command(Some("source env.sh"), Some("/w"), "nvidia-smi");
        assert_eq!(
            script,
            "set -euo pipefail\nset +u\nsource env.sh\nset -u\nmkdir -p '/w' && cd '/w'\nnvidia-smi\n"
        );
        assert_eq!(wrap_command(None, None, "ls"), "set -euo pipefail\nls\n");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn normalize_uuid_accepts_compact_and_dashed_forms() {
        assert_eq!(
            normalize_uuid("AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE").unwrap(),
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        );
        assert!(normalize_uuid("nope").is_none());
    }

    #[test]
    fn metadata_overlay_joins_by_uuid_and_warns_on_bad_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosts.yaml");
        std::fs::write(
            &path,
            "hosts:\n  a:\n    asset_id: AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE\n    env_setup: source x\n    platform: nope\n    workdir: /w\n",
        )
        .unwrap();
        let mut warnings = Vec::new();
        let metadata = asset_metadata(Some(&path), &mut warnings).unwrap();
        let overlay = metadata
            .get("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            .unwrap();
        assert_eq!(overlay.env_setup.as_deref(), Some("source x"));
        assert_eq!(overlay.workdir.as_deref(), Some("/w"));
        assert_eq!(overlay.platform, None);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("platform key")));
    }
}
