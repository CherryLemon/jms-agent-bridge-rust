//! JumpServer REST control plane.
//!
//! Used for what the API is good at: discovering the assets and accounts an account
//! may reach. Anything that *executes* on a host goes through the SSH data plane.
//!
//! Authentication supports the two stable unattended schemes: a private token
//! (`Authorization: Token …`), a session token (`Bearer …`), and an access key using
//! JumpServer's HTTP Signature scheme (HMAC-SHA256 over
//! `(request-target) date accept`, base64-encoded).

use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::config::BastionConfig;
use crate::errors::{BridgeError, BridgeResult};

type HmacSha256 = Hmac<Sha256>;

/// Headers bound into the signature, in the order JumpServer's verifier expects.
pub const SIGNED_HEADERS: [&str; 3] = ["(request-target)", "date", "accept"];

const UNRESERVED: &[u8] = b"-._~";

/// RFC 3986 percent encoding; spaces become `%20`, never `+`.
pub fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || UNRESERVED.contains(byte) {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn encode_query(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Return `(authorization_header, headers_to_send)` for an access-key request.
pub fn sign_access_key(
    access_key_id: &str,
    access_key_secret: &str,
    method: &str,
    path: &str,
    date: &str,
    accept: &str,
    org: Option<&str>,
) -> (String, Vec<(String, String)>) {
    let mut headers = vec![
        ("date".to_string(), date.to_string()),
        ("accept".to_string(), accept.to_string()),
    ];
    let mut signed: Vec<&str> = SIGNED_HEADERS.to_vec();
    if let Some(org) = org {
        headers.push(("x-jms-org".to_string(), org.to_string()));
        signed.push("x-jms-org");
    }
    let lines: Vec<String> = signed
        .iter()
        .map(|header| {
            if *header == "(request-target)" {
                format!("(request-target): {} {path}", method.to_lowercase())
            } else {
                let value = headers
                    .iter()
                    .find(|(name, _)| name == header)
                    .map(|(_, value)| value.as_str())
                    .unwrap_or("");
                format!("{header}: {value}")
            }
        })
        .collect();
    let signable = lines.join("\n");
    let mut mac = HmacSha256::new_from_slice(access_key_secret.as_bytes())
        .expect("HMAC accepts arbitrary key length");
    mac.update(signable.as_bytes());
    let signature = BASE64.encode(mac.finalize().into_bytes());
    let authorization = format!(
        "Signature keyId=\"{access_key_id}\",algorithm=\"hmac-sha256\",signature=\"{signature}\",headers=\"{}\"",
        signed.join(" ")
    );
    (authorization, headers)
}

pub struct ApiClient {
    pub cfg: BastionConfig,
    client: reqwest::Client,
    token: Mutex<Option<String>>,
}

impl ApiClient {
    pub fn new(cfg: BastionConfig, proxy: Option<&str>) -> BridgeResult<Self> {
        crate::tls::install_default_provider();
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs_f64(cfg.api_timeout.max(0.5)))
            .danger_accept_invalid_certs(!cfg.verify_tls);
        let proxy_url = proxy.map(str::to_string).or_else(env_proxy);
        if let Some(proxy_url) = proxy_url {
            let proxy = reqwest::Proxy::all(&proxy_url)
                .map_err(|error| BridgeError::config(format!("invalid REST proxy: {error}")))?;
            builder = builder.proxy(proxy);
        } else {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|error| BridgeError::rest(format!("HTTP client: {error}")))?;
        Ok(Self {
            cfg,
            client,
            token: Mutex::new(None),
        })
    }

    fn auth_headers(&self, method: &str, path: &str) -> BridgeResult<Vec<(String, String)>> {
        if let (Some(id), Some(secret)) = (&self.cfg.access_key_id, &self.cfg.access_key_secret) {
            let date = httpdate::fmt_http_date(std::time::SystemTime::now());
            let (authorization, headers) = sign_access_key(
                id,
                secret,
                method,
                path,
                &date,
                "application/json",
                self.cfg.org_id.as_deref(),
            );
            let mut out = vec![("Authorization".to_string(), authorization)];
            for (name, value) in headers {
                let name = match name.as_str() {
                    "date" => "Date".to_string(),
                    "accept" => "Accept".to_string(),
                    "x-jms-org" => "X-JMS-Org".to_string(),
                    other => other.to_string(),
                };
                out.push((name, value));
            }
            return Ok(out);
        }
        if let Some(token) = self.token.lock().expect("token lock").clone() {
            return Ok(vec![(
                "Authorization".to_string(),
                format!("Bearer {token}"),
            )]);
        }
        if let Some(token) = &self.cfg.session_token {
            return Ok(vec![(
                "Authorization".to_string(),
                format!("Bearer {token}"),
            )]);
        }
        if let Some(token) = &self.cfg.private_token {
            return Ok(vec![(
                "Authorization".to_string(),
                format!("Token {token}"),
            )]);
        }
        Err(BridgeError::rest(
            "No JumpServer credentials configured. Run `jms-bridge login`, or set JMS_BRIDGE_SESSION_TOKEN / JMS_BRIDGE_PRIVATE_TOKEN / JMS_BRIDGE_ACCESS_KEY_ID + JMS_BRIDGE_ACCESS_KEY_SECRET.",
        ))
    }

    /// Perform one REST call, signing the exact request target that goes on the wire.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        params: &[(String, String)],
        body: Option<&Value>,
    ) -> BridgeResult<Value> {
        let mut url = self.cfg.api_url(path);
        let query = encode_query(params);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query);
        }
        // JumpServer verifies the signature against `request.get_full_path()`, i.e.
        // the API base prefix plus the query string exactly as sent.
        let signed_path = url
            .strip_prefix(self.cfg.url.trim_end_matches('/'))
            .filter(|rest| !rest.is_empty())
            .unwrap_or("/");
        let mut headers = self.auth_headers(method, signed_path)?;
        if body.is_some() {
            headers.push(("Content-Type".to_string(), "application/json".to_string()));
        }
        let mut builder = match method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            "DELETE" => self.client.delete(&url),
            other => self.client.request(
                reqwest::Method::from_bytes(other.as_bytes())
                    .map_err(|_| BridgeError::rest("invalid HTTP method"))?,
                &url,
            ),
        };
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = body {
            builder = builder.body(serde_json::to_vec(body)?);
        }
        let response = builder.send().await.map_err(|error| {
            BridgeError::rest(format!(
                "{method} {path} -> {}: {error}",
                transport_kind(&error)
            ))
        })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| BridgeError::rest(format!("{method} {path} -> body: {error}")))?;
        if !status.is_success() {
            let preview: String = text.chars().take(500).collect();
            return Err(BridgeError::rest(format!(
                "{method} {path} -> {}: {preview}",
                status.as_u16()
            )));
        }
        if text.is_empty() {
            return Ok(Value::Object(Default::default()));
        }
        match serde_json::from_str::<Value>(&text) {
            Ok(value) => Ok(value),
            Err(_) => {
                let mut map = serde_json::Map::new();
                map.insert("_raw".into(), Value::from(text));
                Ok(Value::Object(map))
            }
        }
    }

    /// Assets this account may reach, plus whether the walk was cut short.
    pub async fn list_assets(
        &self,
        search: Option<&str>,
        limit: usize,
        max_pages: usize,
    ) -> BridgeResult<(Vec<Value>, bool)> {
        let mut out: Vec<Value> = Vec::new();
        let mut truncated = false;
        let mut offset = 0usize;
        let max_pages = max_pages.max(1);
        for page_number in 0..max_pages {
            let mut params: Vec<(String, String)> = vec![
                ("limit".into(), limit.to_string()),
                ("offset".into(), offset.to_string()),
            ];
            if let Some(search) = search.filter(|value| !value.is_empty()) {
                params.push(("q".into(), search.to_string()));
            }
            let data = self
                .request("GET", "perms/users/my/assets/", &params, None)
                .await?;
            match data {
                Value::Array(rows) => {
                    out.extend(rows);
                    break;
                }
                Value::Object(map) => {
                    let page = map
                        .get("results")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let short = page.len() < limit;
                    out.extend(page);
                    let has_next = map.get("next").map(|next| !next.is_null()).unwrap_or(false);
                    if !has_next || short {
                        break;
                    }
                    offset += limit;
                    if page_number == max_pages - 1 {
                        truncated = true;
                    }
                }
                other => {
                    return Err(BridgeError::rest(format!(
                        "unexpected asset list payload: {}",
                        short_type(&other)
                    )))
                }
            }
        }
        Ok((out, truncated))
    }

    pub async fn get_asset(&self, asset_id: &str) -> BridgeResult<Value> {
        self.request(
            "GET",
            &format!("perms/users/my/assets/{asset_id}/"),
            &[],
            None,
        )
        .await
    }

    /// Product version from the unauthenticated public-settings endpoint.
    /// `GET /api/health/` — public endpoint used by `doctor`.
    pub async fn health(&self) -> BridgeResult<Value> {
        self.request("GET", "api/health/", &[], None).await
    }

    pub async fn version(&self) -> Option<String> {
        let data = self
            .request("GET", "settings/public/open/", &[], None)
            .await
            .ok()?;
        data.get("INTERFACE")
            .and_then(|interface| interface.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

fn env_proxy() -> Option<String> {
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn transport_kind(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "ConnectTimeout"
    } else if error.is_connect() {
        "ConnectError"
    } else if error.is_body() {
        "BodyError"
    } else {
        "HTTPError"
    }
}

fn short_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_pyhttpsig_layout() {
        let (authorization, headers) = sign_access_key(
            "key-id",
            "secret",
            "GET",
            "/api/v1/perms/users/my/assets/?limit=200&offset=0",
            "Thu, 01 Jan 1970 00:00:00 GMT",
            "application/json",
            None,
        );
        assert!(authorization
            .starts_with("Signature keyId=\"key-id\",algorithm=\"hmac-sha256\",signature=\""));
        assert!(authorization.ends_with("headers=\"(request-target) date accept\""));
        assert_eq!(headers.len(), 2);
        // Verified independently: HMAC-SHA256 over the three signed lines.
        let signable = "(request-target): get /api/v1/perms/users/my/assets/?limit=200&offset=0\ndate: Thu, 01 Jan 1970 00:00:00 GMT\naccept: application/json";
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(signable.as_bytes());
        let expected = BASE64.encode(mac.finalize().into_bytes());
        assert!(authorization.contains(&format!("signature=\"{expected}\"")));
    }

    #[test]
    fn org_header_joins_the_signature() {
        let (authorization, headers) = sign_access_key(
            "id",
            "s",
            "GET",
            "/x",
            "date",
            "application/json",
            Some("org-1"),
        );
        assert!(authorization.contains("headers=\"(request-target) date accept x-jms-org\""));
        assert!(headers
            .iter()
            .any(|(name, value)| name == "x-jms-org" && value == "org-1"));
    }

    #[test]
    fn query_encoding_is_rfc3986() {
        let params = vec![
            ("q".to_string(), "a b".to_string()),
            ("limit".to_string(), "200".to_string()),
            ("x".to_string(), "/y&z".to_string()),
        ];
        assert_eq!(encode_query(&params), "q=a%20b&limit=200&x=%2Fy%26z");
    }

    #[test]
    fn api_url_joins_without_double_slashes() {
        let cfg = BastionConfig {
            url: "https://bastion.example/".into(),
            api_base: "/api/v1".into(),
            ..Default::default()
        };
        assert_eq!(
            cfg.api_url("/perms/users/my/assets/"),
            "https://bastion.example/api/v1/perms/users/my/assets/"
        );
    }
}
