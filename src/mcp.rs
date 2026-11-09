//! The single compact MCP surface: seven tools over one resident runtime.

use std::collections::HashMap;
use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::ErrorData as McpError;
use serde_json::{json, Map, Value};

use crate::errors::BridgeError;
use crate::runtime::{string_list, BridgeRuntime};
use crate::schemas;
use crate::views;

pub struct BridgeServer {
    pub runtime: Arc<BridgeRuntime>,
    tools: Vec<Tool>,
}

impl BridgeServer {
    pub fn new(runtime: Arc<BridgeRuntime>) -> Self {
        let tools = schemas::advertised()
            .into_iter()
            .map(|spec| {
                let schema: Map<String, Value> = match spec.input_schema {
                    Value::Object(map) => map,
                    _ => Map::new(),
                };
                let mut tool = Tool::new(spec.name, spec.description, schema);
                tool.annotations = Some(ToolAnnotations::from_raw(
                    None,
                    Some(spec.read_only),
                    Some(spec.destructive),
                    None,
                    Some(spec.open_world),
                ));
                tool
            })
            .collect();
        Self { runtime, tools }
    }

    pub fn tool_specs(&self) -> Vec<Tool> {
        self.tools.clone()
    }

    /// Validate, merge advanced options and dispatch, then compact the answer.
    pub async fn dispatch(
        &self,
        name: &str,
        arguments: Map<String, Value>,
    ) -> Result<Value, BridgeError> {
        // Validate against the complete definition: the advertised schema is a
        // token-saving subset, not the contract.
        let spec = schemas::full_specs()
            .into_iter()
            .find(|spec| spec.name == name)
            .ok_or_else(|| BridgeError::invalid(format!("unknown tool {name:?}")))?;
        // `detail` was advertised by earlier releases; it is accepted (and honoured)
        // without spending tokens on it in every schema.
        let mut arguments = arguments;
        let detail = arguments
            .remove("detail")
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "compact".to_string());
        if !matches!(detail.as_str(), "compact" | "full") {
            return Err(BridgeError::invalid("detail must be compact or full"));
        }
        let flat = flatten_options(name, arguments.clone())?;
        crate::schema::validate(&spec.input_schema, &Value::Object(arguments.clone())).map_err(
            |error| {
                BridgeError::invalid(format!(
                    "Invalid arguments at {}: {}",
                    if error.path.is_empty() {
                        "<args>".to_string()
                    } else {
                        error.path.clone()
                    },
                    error.message
                ))
            },
        )?;
        let value = match name {
            "run" => self.runtime.tool_run(flat.clone()).await?,
            "fs" => self.runtime.tool_fs(flat.clone()).await?,
            "terminal" => {
                let action = flat
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or("exec")
                    .to_string();
                self.runtime.tool_terminal(&action, flat.clone()).await?
            }
            "read_result" => self.runtime.tool_read_result(&flat)?,
            "discover" => self.runtime.tool_discover(&flat).await?,
            "call" => self.runtime.tool_call(flat.clone()).await?,
            "meta" => self.runtime.tool_meta(&flat).await?,
            other => return Err(BridgeError::invalid(format!("unknown tool {other:?}"))),
        };
        if detail == "full" {
            return Ok(value);
        }
        let addresses = self.addresses();
        Ok(views::compact(name, &value, &flat, &addresses))
    }

    fn addresses(&self) -> HashMap<String, String> {
        self.runtime.catalog.addresses()
    }
}

/// Merge the `options` object for `run`/`fs`/`terminal` and reject unsafe overrides.
fn flatten_options(
    name: &str,
    arguments: Map<String, Value>,
) -> Result<Map<String, Value>, BridgeError> {
    let mut arguments = arguments;
    let options = match arguments.remove("options") {
        Some(Value::Object(map)) => map,
        Some(Value::Null) | None => Map::new(),
        Some(_) => return Err(BridgeError::invalid("options must be an object")),
    };
    if options.is_empty() {
        return Ok(arguments);
    }
    if !matches!(name, "run" | "fs" | "terminal") {
        return Err(BridgeError::invalid("this tool takes no options object"));
    }
    let identity: &[&str] = match name {
        "terminal" => &["action"],
        _ => &["targets", "target", "action"],
    };
    for (key, value) in options {
        if identity.contains(&key.as_str()) {
            return Err(BridgeError::invalid(format!(
                "options must not redefine {key}; pass it as a top-level argument"
            )));
        }
        if arguments.contains_key(&key) {
            return Err(BridgeError::invalid(format!("duplicate options: {key}")));
        }
        arguments.insert(key, value);
    }
    Ok(arguments)
}

fn render(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{\"ok\":false}".to_string())
}

impl ServerHandler for BridgeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("jms-bridge", crate::version()))
            .with_instructions(crate::INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        let arguments = request.arguments.unwrap_or_default();
        let runtime = self.runtime.clone();
        let tools = self.tools.clone();
        // Run the request in a service-owned task: a client that disconnects cannot
        // cancel an accepted execution half way through a transfer.
        let server = BridgeServer { runtime, tools };
        let result = tokio::spawn(async move { server.dispatch(&name, arguments).await })
            .await
            .map_err(|error| {
                McpError::internal_error(format!("bridge task failed: {error}"), None)
            })?;
        match result {
            Ok(value) => {
                Ok(CallToolResult::success(vec![ContentBlock::text(render(&value))]).into())
            }
            Err(error) => {
                let body = json!({"ok": false, "error": error.message()});
                Ok(CallToolResult::error(vec![ContentBlock::text(render(&body))]).into())
            }
        }
    }
}

/// Tools whose results are always compact, exposed for diagnostics.
pub fn compact_tools() -> Vec<&'static str> {
    vec![
        "run",
        "fs",
        "terminal",
        "read_result",
        "discover",
        "call",
        "meta",
    ]
}

/// Targets named by one request, used by the service log.
pub fn targets_of(arguments: &Map<String, Value>) -> Vec<String> {
    let mut targets = string_list(arguments.get("targets"));
    if let Some(target) = arguments.get("target").and_then(Value::as_str) {
        targets.push(target.to_string());
    }
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_cannot_shadow_top_level_arguments() {
        let arguments = json!({"targets": ["a"], "options": {"timeout": 30}});
        let flat = flatten_options("run", arguments.as_object().unwrap().clone()).unwrap();
        assert_eq!(flat.get("timeout"), Some(&json!(30)));
    }

    #[test]
    fn options_reject_duplicates_and_identity() {
        let duplicate = json!({"targets": ["a"], "timeout": 5, "options": {"timeout": 30}});
        assert!(flatten_options("run", duplicate.as_object().unwrap().clone()).is_err());
        let identity = json!({"targets": ["a"], "options": {"targets": ["b"]}});
        assert!(flatten_options("run", identity.as_object().unwrap().clone()).is_err());
    }

    #[test]
    fn options_are_only_accepted_by_option_taking_tools() {
        let arguments = json!({"options": {"limit": 5}});
        assert!(flatten_options("discover", arguments.as_object().unwrap().clone()).is_err());
    }
}
