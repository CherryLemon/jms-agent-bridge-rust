//! Configuration: `~/.config/jms-bridge/config.toml` plus environment overrides.
//!
//! Secrets are never required to live in the file: every value can be supplied or
//! overridden from the environment. The one secret that may be persisted is the
//! SSH password, which `jms-bridge login --save-password` writes to a separate
//! mode-600 `credentials.toml`; deleting that file revokes it.

use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::errors::{BridgeError, BridgeResult};
use crate::inventory::home_dir;

pub const DEFAULT_CONFIG_PATH: &str = "~/.config/jms-bridge/config.toml";
pub const DEFAULT_CREDENTIALS_PATH: &str = "~/.config/jms-bridge/credentials.toml";

#[derive(Debug, Clone)]
pub struct BastionConfig {
    pub url: String,
    pub ssh_port: u16,
    pub login_user: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub verify_tls: bool,
    pub api_timeout: f64,
    pub max_parallel: usize,
    pub org_id: Option<String>,
    pub access_key_id: Option<String>,
    pub access_key_secret: Option<String>,
    pub private_token: Option<String>,
    pub session_token: Option<String>,
    pub ssh_password: Option<String>,
    pub api_base: String,
}

impl Default for BastionConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            ssh_port: 2222,
            login_user: None,
            ssh_key: None,
            verify_tls: true,
            api_timeout: 30.0,
            max_parallel: 8,
            org_id: None,
            access_key_id: None,
            access_key_secret: None,
            private_token: None,
            session_token: None,
            ssh_password: None,
            api_base: "/api/v1".into(),
        }
    }
}

impl BastionConfig {
    pub fn api_url(&self, path: &str) -> String {
        format!(
            "{}{}/{}",
            self.url.trim_end_matches('/'),
            self.api_base,
            path.trim_start_matches('/')
        )
    }

    /// Whether any REST credential is configured.
    pub fn has_credentials(&self) -> bool {
        (self.access_key_id.is_some() && self.access_key_secret.is_some())
            || self.session_token.is_some()
            || self.private_token.is_some()
    }

    /// The identity REST permissions are bound to; a cache key, never a secret dump.
    pub fn credential_identity(&self) -> Vec<Option<String>> {
        vec![
            Some(self.url.clone()),
            self.org_id.clone(),
            self.login_user.clone(),
            self.access_key_id.clone(),
            self.access_key_secret.clone(),
            self.private_token.clone(),
            self.session_token.clone(),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct BridgeSettings {
    pub state_dir: PathBuf,
    pub refresh_interval: u64,
    pub execution_limit: Option<usize>,
    pub inspection_reserved: usize,
    pub queue_timeout: f64,
    pub queue_limit: usize,
    pub inspection_queue_limit: usize,
    pub result_ttl_seconds: f64,
    pub result_cleanup_interval_seconds: f64,
    pub preferred_account: Option<String>,
    pub rest_proxy: Option<String>,
    pub ssh_host: Option<String>,
    pub ssh_proxy_command: Vec<String>,
    pub known_hosts: Option<PathBuf>,
    pub host_key_alias: Option<String>,
}

impl Default for BridgeSettings {
    fn default() -> Self {
        Self {
            state_dir: default_state_dir(),
            refresh_interval: 3600,
            execution_limit: None,
            inspection_reserved: 0,
            queue_timeout: 60.0,
            queue_limit: 64,
            inspection_queue_limit: 16,
            result_ttl_seconds: 604_800.0,
            result_cleanup_interval_seconds: 3600.0,
            preferred_account: None,
            rest_proxy: None,
            ssh_host: None,
            ssh_proxy_command: Vec::new(),
            known_hosts: None,
            host_key_alias: None,
        }
    }
}

impl BridgeSettings {
    /// known_hosts file used to verify the gateway's host key.
    ///
    /// Verification is never skipped implicitly: without an explicit setting the
    /// conventional `~/.ssh/known_hosts` is used, and when neither exists the
    /// connection is refused instead of trusting an unverified key.
    pub fn resolve_known_hosts(&self) -> BridgeResult<PathBuf> {
        self.resolve_known_hosts_in(&home_dir()?)
    }

    fn resolve_known_hosts_in(&self, home: &Path) -> BridgeResult<PathBuf> {
        if let Some(path) = &self.known_hosts {
            if path.is_file() {
                return Ok(path.clone());
            }
            return Err(BridgeError::config(format!(
                "known_hosts file {} does not exist; SSH host key verification is never skipped",
                path.display()
            )));
        }
        let default = home.join(".ssh/known_hosts");
        if default.is_file() {
            return Ok(default);
        }
        Err(BridgeError::config(
            "SSH host key verification is not configured: create ~/.ssh/known_hosts or set \
bridge.known_hosts (JMS_BRIDGE_KNOWN_HOSTS). Refusing to connect to an unverified gateway.",
        ))
    }

    /// Host the KoKo SSH gateway is reached on.
    pub fn gateway_host(&self, cfg: &BastionConfig) -> BridgeResult<String> {
        if let Some(host) = &self.ssh_host {
            return Ok(host.clone());
        }
        let parsed = url::Url::parse(&cfg.url)
            .map_err(|_| BridgeError::config("configure bridge.ssh_host or a valid bastion.url"))?;
        parsed
            .host_str()
            .map(str::to_string)
            .ok_or_else(|| BridgeError::config("configure bridge.ssh_host or a valid bastion.url"))
    }
}

pub fn expand_tilde(value: &str) -> PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        return home_dir()
            .map(|home| home.join(rest))
            .unwrap_or_else(|_| PathBuf::from(value));
    }
    if value == "~" {
        return home_dir().unwrap_or_else(|_| PathBuf::from(value));
    }
    PathBuf::from(value)
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(value) = env_value("JMS_BRIDGE_CONFIG") {
        return expand_tilde(&value);
    }
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    expand_tilde(DEFAULT_CONFIG_PATH)
}

pub fn credentials_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(value) = env_value("JMS_BRIDGE_CREDENTIALS") {
        return expand_tilde(&value);
    }
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    expand_tilde(DEFAULT_CREDENTIALS_PATH)
}

pub fn default_state_dir() -> PathBuf {
    if let Some(value) = env_value("JMS_BRIDGE_STATE_DIR") {
        return expand_tilde(&value);
    }
    let base = match env_value("XDG_STATE_HOME") {
        Some(value) => expand_tilde(&value),
        None => home_dir()
            .map(|home| home.join(".local/state"))
            .unwrap_or_else(|_| PathBuf::from(".local/state")),
    };
    base.join("jms-bridge")
}

/// Parse a TOML file, returning `{}` when it does not exist.
pub fn read_toml(path: &Path) -> BridgeResult<toml::Value> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str::<toml::Value>(&text).map_err(|error| {
            BridgeError::config(format!("{} is not valid TOML: {error}", path.display()))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(toml::Value::Table(Default::default()))
        }
        Err(error) => Err(BridgeError::config(format!(
            "cannot read {}: {error}",
            path.display()
        ))),
    }
}

fn table(value: &toml::Value, key: &str) -> toml::map::Map<String, toml::Value> {
    value
        .get(key)
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default()
}

fn as_string(map: &toml::map::Map<String, toml::Value>, key: &str) -> Option<String> {
    map.get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn as_bool(map: &toml::map::Map<String, toml::Value>, key: &str) -> Option<bool> {
    map.get(key).and_then(toml::Value::as_bool)
}

fn as_i64(map: &toml::map::Map<String, toml::Value>, key: &str) -> Option<i64> {
    map.get(key).and_then(toml::Value::as_integer)
}

fn as_f64(map: &toml::map::Map<String, toml::Value>, key: &str) -> Option<f64> {
    match map.get(key) {
        Some(toml::Value::Float(value)) => Some(*value),
        Some(toml::Value::Integer(value)) => Some(*value as f64),
        _ => None,
    }
}

/// `[credentials]` table of a credential file; empty when it cannot be read.
fn credentials_from(path: &Path) -> toml::map::Map<String, toml::Value> {
    match read_toml(path) {
        Ok(data) => table(&data, "credentials"),
        Err(_) => toml::map::Map::new(),
    }
}

fn credential_value(
    credentials: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Option<String> {
    credentials
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

fn credential_text(key: &str) -> Option<String> {
    credential_value(&credentials_from(&credentials_path(None)), key)
}

/// Load the persisted SSH password saved by `jms-bridge login --save-password`.
pub fn stored_password() -> Option<String> {
    if let Some(value) = env_value("JMS_BRIDGE_PASSWORD") {
        return Some(value);
    }
    let path = credentials_path(None);
    let data = read_toml(&path).ok()?;
    let credentials = table(&data, "credentials");
    credentials
        .get("password")
        .and_then(toml::Value::as_str)
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

pub fn load_config(explicit: Option<&Path>) -> BridgeResult<BastionConfig> {
    let path = config_path(explicit);
    let data = read_toml(&path)?;
    let bastion = table(&data, "bastion");

    let url = env_value("JMS_BRIDGE_URL")
        .or_else(|| as_string(&bastion, "url"))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            BridgeError::config(format!(
                "No bastion URL configured. Set 'bastion.url' in {} or the JMS_BRIDGE_URL environment variable.",
                path.display()
            ))
        })?;

    let verify_tls = match env_value("JMS_BRIDGE_VERIFY_TLS") {
        Some(value) => !matches!(value.to_lowercase().as_str(), "0" | "false" | "no"),
        None => as_bool(&bastion, "verify_tls").unwrap_or(true),
    };

    let ssh_key = env_value("JMS_BRIDGE_SSH_KEY").or_else(|| as_string(&bastion, "ssh_key"));
    let ssh_password = env_value("JMS_BRIDGE_SSH_PASSWORD")
        .or_else(|| as_string(&bastion, "ssh_password"))
        .or_else(stored_password);

    let ssh_port = match env_value("JMS_BRIDGE_SSH_PORT") {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| BridgeError::config("JMS_BRIDGE_SSH_PORT must be a port number"))?,
        None => as_i64(&bastion, "ssh_port").unwrap_or(2222) as u16,
    };

    let max_parallel = match env_value("JMS_BRIDGE_MAX_PARALLEL") {
        Some(value) => positive_int(&value, "max_parallel (JMS_BRIDGE_MAX_PARALLEL)")?,
        None => match as_i64(&bastion, "max_parallel") {
            Some(value) if value >= 1 => value as usize,
            Some(value) => {
                return Err(BridgeError::config(format!(
                    "max_parallel must be at least 1, got {value}"
                )))
            }
            None => 8,
        },
    };

    Ok(BastionConfig {
        url: url.trim_end_matches('/').to_string(),
        ssh_port,
        login_user: env_value("JMS_BRIDGE_LOGIN_USER")
            .or_else(|| as_string(&bastion, "login_user")),
        ssh_key: ssh_key.map(|value| expand_tilde(&value)),
        ssh_password,
        verify_tls,
        api_timeout: as_f64(&bastion, "api_timeout").unwrap_or(30.0),
        max_parallel,
        org_id: env_value("JMS_BRIDGE_ORG_ID").or_else(|| as_string(&bastion, "org_id")),
        access_key_id: env_value("JMS_BRIDGE_ACCESS_KEY_ID")
            .or_else(|| as_string(&bastion, "access_key_id"))
            .or_else(|| credential_text("access_key_id")),
        access_key_secret: env_value("JMS_BRIDGE_ACCESS_KEY_SECRET")
            .or_else(|| as_string(&bastion, "access_key_secret"))
            .or_else(|| credential_text("access_key_secret")),
        private_token: env_value("JMS_BRIDGE_PRIVATE_TOKEN")
            .or_else(|| as_string(&bastion, "private_token"))
            .or_else(|| credential_text("private_token")),
        session_token: env_value("JMS_BRIDGE_SESSION_TOKEN")
            .or_else(|| as_string(&bastion, "session_token"))
            .or_else(|| credential_text("session_token")),
        api_base: as_string(&bastion, "api_base").unwrap_or_else(|| "/api/v1".into()),
    })
}

fn positive_int(value: &str, what: &str) -> BridgeResult<usize> {
    let parsed = value
        .parse::<i64>()
        .map_err(|_| BridgeError::config(format!("{what} must be an integer, got {value:?}")))?;
    if parsed < 1 {
        return Err(BridgeError::config(format!(
            "{what} must be at least 1, got {parsed}"
        )));
    }
    Ok(parsed as usize)
}

pub fn load_settings(explicit: Option<&Path>) -> BridgeResult<BridgeSettings> {
    let path = config_path(explicit);
    let data = read_toml(&path)?;
    let bridge = table(&data, "bridge");

    let interval = match as_i64(&bridge, "refresh_interval") {
        Some(value) if value >= 1 => value as u64,
        Some(_) => {
            return Err(BridgeError::config(
                "bridge.refresh_interval must be a positive integer",
            ))
        }
        None => 3600,
    };
    let execution_limit = match bridge.get("execution_limit") {
        None => None,
        Some(toml::Value::Integer(value)) if *value >= 1 => Some(*value as usize),
        Some(_) => {
            return Err(BridgeError::config(
                "bridge.execution_limit must be a valid integer",
            ))
        }
    };
    let inspection_reserved = match bridge.get("inspection_reserved") {
        None => 0,
        Some(toml::Value::Integer(value)) if *value >= 0 => *value as usize,
        Some(_) => {
            return Err(BridgeError::config(
                "bridge.inspection_reserved must be a valid integer",
            ))
        }
    };
    if let Some(limit) = execution_limit {
        if inspection_reserved >= limit {
            return Err(BridgeError::config(
                "bridge.inspection_reserved must be less than execution_limit",
            ));
        }
    }
    let queue_limit = nonnegative(&bridge, "queue_limit", 64)?;
    let inspection_queue_limit = nonnegative(&bridge, "inspection_queue_limit", 16)?;
    let queue_timeout = positive_float(&bridge, "queue_timeout", 60.0)?;
    let result_ttl_seconds = positive_float(&bridge, "result_ttl_seconds", 604_800.0)?;
    let result_cleanup_interval_seconds =
        positive_float(&bridge, "result_cleanup_interval_seconds", 3600.0)?;

    let mut ssh_proxy_command: Vec<String> = Vec::new();
    match bridge.get("ssh_proxy_command") {
        None => {}
        Some(toml::Value::Array(items)) => {
            for item in items {
                match item.as_str() {
                    Some(text) if !text.is_empty() && !text.contains('\0') => {
                        ssh_proxy_command.push(text.to_string())
                    }
                    _ => {
                        return Err(BridgeError::config(
                            "bridge.ssh_proxy_command must be an argv list of nonempty strings",
                        ))
                    }
                }
            }
        }
        Some(_) => {
            return Err(BridgeError::config(
                "bridge.ssh_proxy_command must be an argv list of nonempty strings",
            ))
        }
    }
    let string_field = |name: &str| -> BridgeResult<Option<String>> {
        match bridge.get(name) {
            None => Ok(None),
            Some(toml::Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
            Some(_) => Err(BridgeError::config(format!(
                "bridge.{name} must be a nonempty string"
            ))),
        }
    };
    let preferred_account = string_field("preferred_account")?;
    let rest_proxy = string_field("rest_proxy")?;
    let ssh_host = string_field("ssh_host")?;
    let host_key_alias = string_field("host_key_alias")?;
    let known_hosts = string_field("known_hosts")?.map(|value| expand_tilde(&value));
    let state_dir = match env_value("JMS_BRIDGE_STATE_DIR").or(string_field("state_dir")?) {
        Some(value) => expand_tilde(&value),
        None => default_state_dir(),
    };

    Ok(BridgeSettings {
        state_dir,
        refresh_interval: interval,
        execution_limit,
        inspection_reserved,
        queue_timeout,
        queue_limit,
        inspection_queue_limit,
        result_ttl_seconds,
        result_cleanup_interval_seconds,
        preferred_account,
        rest_proxy,
        ssh_host,
        ssh_proxy_command,
        known_hosts,
        host_key_alias,
    })
}

fn nonnegative(
    map: &toml::map::Map<String, toml::Value>,
    key: &str,
    default: usize,
) -> BridgeResult<usize> {
    match map.get(key) {
        None => Ok(default),
        Some(toml::Value::Integer(value)) if *value >= 0 => Ok(*value as usize),
        Some(_) => Err(BridgeError::config(format!(
            "bridge.{key} must be a nonnegative integer"
        ))),
    }
}

fn positive_float(
    map: &toml::map::Map<String, toml::Value>,
    key: &str,
    default: f64,
) -> BridgeResult<f64> {
    match map.get(key) {
        None => Ok(default),
        Some(toml::Value::Float(value)) if value.is_finite() && *value > 0.0 => Ok(*value),
        Some(toml::Value::Integer(value)) if *value > 0 => Ok(*value as f64),
        Some(_) => Err(BridgeError::config(format!(
            "bridge.{key} must be positive and finite"
        ))),
    }
}

/// One resident process owns a state directory and its shell registries.
pub struct StateLock {
    file: Option<std::fs::File>,
    path: PathBuf,
}

impl StateLock {
    pub fn acquire(directory: &Path) -> BridgeResult<Self> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join("service.lock");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(BridgeError::config(
                "state directory is already in use; connect to the resident HTTP service or configure a separate bridge.state_dir",
            ));
        }
        Ok(Self {
            file: Some(file),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn write_config(body: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("config.toml"), body).unwrap();
        directory
    }

    #[test]
    fn credential_file_supplies_tokens_and_keys() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("credentials.toml");
        std::fs::write(
            &path,
            "[credentials]\nsession_token = \"token-value\"\nprivate_token = \"\"\naccess_key_id = \"kid\"\n",
        )
        .unwrap();
        let credentials = credentials_from(&path);
        assert_eq!(
            credential_value(&credentials, "session_token").as_deref(),
            Some("token-value")
        );
        assert_eq!(credential_value(&credentials, "private_token"), None);
        assert_eq!(
            credential_value(&credentials, "access_key_id").as_deref(),
            Some("kid")
        );
    }

    #[test]
    fn missing_credential_file_is_silent() {
        let directory = tempfile::tempdir().unwrap();
        let credentials = credentials_from(&directory.path().join("absent.toml"));
        assert!(credentials.is_empty());
    }

    #[test]
    fn known_hosts_defaults_to_the_ssh_file() {
        let home = tempfile::tempdir().unwrap();
        let ssh = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        let known_hosts = ssh.join("known_hosts");
        std::fs::write(&known_hosts, "bastion.example ssh-ed25519 AAAA\n").unwrap();
        let settings = BridgeSettings::default();
        let resolved = settings.resolve_known_hosts_in(home.path()).unwrap();
        assert_eq!(resolved, known_hosts);
    }

    #[test]
    fn missing_known_hosts_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let settings = BridgeSettings::default();
        let error = settings.resolve_known_hosts_in(home.path()).unwrap_err();
        assert!(error.message().contains("host key verification"));
    }

    #[test]
    fn configured_known_hosts_must_exist() {
        let directory = tempfile::tempdir().unwrap();
        let mut settings = BridgeSettings::default();
        settings.known_hosts = Some(directory.path().join("absent"));
        let error = settings
            .resolve_known_hosts_in(directory.path())
            .unwrap_err();
        assert!(error.message().contains("does not exist"));
    }

    #[test]
    fn shipped_example_config_loads() {
        let example = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/config.toml");
        let data = read_toml(&example).unwrap();
        let bastion = table(&data, "bastion");
        assert_eq!(
            as_string(&bastion, "url").as_deref(),
            Some("https://bastion.example.com")
        );
        assert_eq!(as_i64(&bastion, "ssh_port"), Some(2224));
        // Settings live under [bridge]; the example must not put them under [bastion].
        assert!(data.get("bridge").and_then(toml::Value::as_table).is_some());
        assert_eq!(as_string(&bastion, "state_dir"), None);
        assert_eq!(as_string(&bastion, "queue_limit"), None);
    }

    #[test]
    fn load_config_reads_bastion_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "[bastion]\nurl = \"https://bastion.example\"\nssh_port = 2224\nlogin_user = \"u\"\nsession_token = \"t\"\n",
        )
        .unwrap();
        let cfg = load_config(Some(&path)).unwrap();
        assert_eq!(cfg.url, "https://bastion.example");
        assert_eq!(cfg.ssh_port, 2224);
        assert_eq!(cfg.login_user.as_deref(), Some("u"));
        assert!(cfg.has_credentials());
        assert_eq!(
            cfg.api_url("/perms/x"),
            "https://bastion.example/api/v1/perms/x"
        );
    }

    #[test]
    fn load_config_requires_url() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[bastion]\nssh_port = 2222\n").unwrap();
        std::env::remove_var("JMS_BRIDGE_URL");
        let error = load_config(Some(&path)).unwrap_err();
        assert!(error.message().contains("No bastion URL configured"));
    }

    #[test]
    fn load_config_rejects_bad_toml() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(&path, "[bastion\nurl = 1").unwrap();
        let error = load_config(Some(&path)).unwrap_err();
        assert!(error.message().contains("not valid TOML"));
    }

    #[test]
    fn settings_validate_bridge_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        std::fs::write(
            &path,
            "[bastion]\nurl = \"https://x\"\n[bridge]\nexecution_limit = 4\ninspection_reserved = 4\n",
        )
        .unwrap();
        let error = load_settings(Some(&path)).unwrap_err();
        assert!(error.message().contains("inspection_reserved"));

        std::fs::write(
            &path,
            "[bastion]\nurl = \"https://x\"\n[bridge]\nexecution_limit = 4\ninspection_reserved = 1\nqueue_timeout = 30\nresult_ttl_seconds = 60\n",
        )
        .unwrap();
        let settings = load_settings(Some(&path)).unwrap();
        assert_eq!(settings.execution_limit, Some(4));
        assert_eq!(settings.inspection_reserved, 1);
        assert_eq!(settings.queue_timeout, 30.0);
        assert_eq!(settings.result_cleanup_interval_seconds, 3600.0);
    }

    #[test]
    fn state_lock_is_exclusive() {
        let directory = tempfile::tempdir().unwrap();
        let first = StateLock::acquire(directory.path()).unwrap();
        let second = StateLock::acquire(directory.path());
        assert!(second.is_err());
        drop(first);
        assert!(StateLock::acquire(directory.path()).is_ok());
    }

    #[test]
    fn gateway_host_prefers_explicit_setting() {
        let cfg = BastionConfig {
            url: "https://bastion.example:443".into(),
            ..Default::default()
        };
        let mut settings = BridgeSettings::default();
        assert_eq!(settings.gateway_host(&cfg).unwrap(), "bastion.example");
        settings.ssh_host = Some("10.0.0.5".into());
        assert_eq!(settings.gateway_host(&cfg).unwrap(), "10.0.0.5");
    }
}
