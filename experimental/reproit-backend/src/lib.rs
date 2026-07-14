//! Experimental, framework-neutral backend instrumentation.
//!
//! Services activate this adapter only when a trusted request carries
//! `x-reproit-trace`. The resulting response header contains bounded,
//! trace-bound, structurally redacted events. It is not a public compatibility
//! surface while backend contracts remain experimental.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_EVENTS: usize = 256;
const MAX_HEADER_BYTES: usize = 60_000;
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub actor: Option<String>,
    pub action_index: u32,
}

impl TraceContext {
    pub fn from_header_fn(mut get: impl FnMut(&str) -> Option<String>) -> Option<Self> {
        let trace_id = bounded(get("x-reproit-trace")?, 128)?;
        let actor = get("x-reproit-actor").and_then(|value| bounded(value, 32));
        let action_index = get("x-reproit-action")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        Some(Self {
            trace_id,
            actor,
            action_index,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Selection {
    pub schema_path: String,
    pub response_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_condition: Option<String>,
}

/// Canonical decoded OpenAPI input. Framework adapters must provide decoded
/// values (including arrays for repeated query/header parameters), never raw
/// query strings whose serialization style is ambiguous.
#[derive(Debug, Default)]
pub struct HttpInput {
    pub body: Option<Value>,
    pub path: BTreeMap<String, Value>,
    pub query: BTreeMap<String, Value>,
    pub headers: BTreeMap<String, Value>,
}

impl HttpInput {
    pub fn into_value(self) -> Value {
        let mut value = Map::new();
        if let Some(body) = self.body {
            value.insert("body".into(), body);
        }
        for (name, fields) in [
            ("path", self.path),
            ("query", self.query),
            (
                "headers",
                self.headers
                    .into_iter()
                    .map(|(key, value)| (key.to_ascii_lowercase(), value))
                    .collect(),
            ),
        ] {
            if !fields.is_empty() {
                value.insert(
                    name.into(),
                    Value::Object(fields.into_iter().collect::<Map<_, _>>()),
                );
            }
        }
        Value::Object(value)
    }
}

impl Selection {
    pub fn new(schema_path: impl Into<String>, response_path: impl Into<String>) -> Option<Self> {
        let selection = Self {
            schema_path: schema_path.into(),
            response_path: response_path.into(),
            type_condition: None,
        };
        (valid_path(&selection.schema_path) && valid_path(&selection.response_path))
            .then_some(selection)
    }

    pub fn with_type_condition(mut self, condition: impl Into<String>) -> Option<Self> {
        let condition = condition.into();
        if !valid_path(&condition) || condition.contains('.') || condition.contains("[]") {
            return None;
        }
        self.type_condition = Some(condition);
        Some(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    InvalidOperation,
    AlreadyFinished,
    TooManyEvents,
    HeaderTooLarge,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    Read,
    Write,
    Delete,
    Emit,
    Call,
}

pub struct BackendTrace {
    common: Map<String, Value>,
    events: Vec<Value>,
    finished: bool,
}

impl BackendTrace {
    pub fn begin(
        context: TraceContext,
        operation: impl Into<String>,
        span_id: Option<String>,
        tenant: Option<String>,
        idempotency_key: Option<&str>,
        input: Value,
        selections: Vec<Selection>,
    ) -> Result<Self, TraceError> {
        let operation = bounded(operation.into(), 256).ok_or(TraceError::InvalidOperation)?;
        let span_id = bounded(
            span_id.unwrap_or_else(|| format!("{}:{operation}", context.trace_id)),
            128,
        )
        .ok_or(TraceError::InvalidOperation)?;
        let mut common = Map::from_iter([
            ("traceId".into(), Value::String(context.trace_id)),
            ("spanId".into(), Value::String(span_id)),
            ("actionIndex".into(), json!(context.action_index)),
            ("operation".into(), Value::String(operation)),
        ]);
        if let Some(actor) = context.actor {
            common.insert("actor".into(), Value::String(actor));
        }
        if let Some(tenant) = tenant.and_then(|value| bounded(value, 128)) {
            common.insert("tenant".into(), Value::String(tenant));
        }
        if let Some(key) = idempotency_key {
            common.insert("idempotencyKey".into(), Value::String(identity(key)));
        }
        if !selections.is_empty() {
            common.insert(
                "selections".into(),
                serde_json::to_value(selections.into_iter().take(MAX_EVENTS).collect::<Vec<_>>())
                    .expect("selection serialization"),
            );
        }
        let mut trace = Self {
            common,
            events: Vec::new(),
            finished: false,
        };
        trace.push("start", Map::from_iter([("input".into(), redact(input))]))?;
        Ok(trace)
    }

    pub fn effect(
        &mut self,
        effect: EffectKind,
        resource: Option<&str>,
        key: Option<&str>,
        tenant: Option<&str>,
        event: Option<&str>,
        detail: Option<Value>,
    ) -> Result<(), TraceError> {
        if self.finished {
            return Err(TraceError::AlreadyFinished);
        }
        let mut fields = Map::from_iter([(
            "effect".into(),
            serde_json::to_value(effect).expect("effect serialization"),
        )]);
        for (name, value) in [
            ("resource", resource),
            ("key", key),
            ("effectTenant", tenant),
            ("event", event),
        ] {
            if let Some(value) = value {
                fields.insert(
                    name.into(),
                    Value::String(value.chars().take(256).collect()),
                );
            }
        }
        if let Some(Value::Object(detail)) = detail.map(redact) {
            fields.extend(
                detail
                    .into_iter()
                    .filter(|(key, _)| matches!(key.as_str(), "before" | "after" | "payload")),
            );
        }
        self.push("effect", fields)
    }

    pub fn finish(
        &mut self,
        output: Value,
        status: u16,
        success: bool,
        effects_complete: bool,
    ) -> Result<(), TraceError> {
        if self.finished {
            return Err(TraceError::AlreadyFinished);
        }
        self.push(
            "return",
            Map::from_iter([
                ("output".into(), redact(output)),
                ("status".into(), json!(status)),
                ("success".into(), json!(success)),
                ("effectsComplete".into(), json!(effects_complete)),
            ]),
        )?;
        self.finished = true;
        Ok(())
    }

    pub fn header(&self) -> Result<String, TraceError> {
        if !self.finished {
            return Err(TraceError::AlreadyFinished);
        }
        let encoded = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&self.events).expect("backend event serialization cannot fail"),
        );
        (encoded.len() <= MAX_HEADER_BYTES)
            .then_some(encoded)
            .ok_or(TraceError::HeaderTooLarge)
    }

    pub fn events(&self) -> &[Value] {
        &self.events
    }

    fn push(&mut self, kind: &str, fields: Map<String, Value>) -> Result<(), TraceError> {
        if self.events.len() >= MAX_EVENTS {
            return Err(TraceError::TooManyEvents);
        }
        let mut event = self.common.clone();
        event.insert(
            "sequence".into(),
            json!(SEQUENCE.fetch_add(1, Ordering::Relaxed)),
        );
        event.insert("kind".into(), Value::String(kind.into()));
        event.extend(fields);
        self.events.push(Value::Object(event));
        Ok(())
    }
}

fn bounded(value: String, maximum: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.chars().count() <= maximum).then(|| value.to_string())
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.split('.').all(|segment| {
            let name = segment.strip_suffix("[]").unwrap_or(segment);
            let mut chars = name.chars();
            chars
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
                && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        })
}

fn identity(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "sha256:{}",
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn secret_field(name: &str) -> bool {
    let name = name
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "email",
        "phone",
        "apikey",
        "publishablekey",
        "privatekey",
        "accesskey",
        "signingkey",
        "idempotencykey",
    ]
    .iter()
    .any(|part| name.contains(part))
}

fn redact(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if secret_field(&key) {
                        metadata(&value)
                    } else {
                        redact(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact).collect()),
        value => value,
    }
}

fn metadata(value: &Value) -> Value {
    let (kind, length) = match value {
        Value::Null => ("null", None),
        Value::Bool(_) => ("boolean", None),
        Value::Number(number) if number.is_i64() || number.is_u64() => ("integer", None),
        Value::Number(_) => ("number", None),
        Value::String(value) => ("string", Some(value.chars().count())),
        Value::Array(value) => ("array", Some(value.len())),
        Value::Object(_) => ("object", None),
    };
    json!({ "$reproit": {
        "redacted": true,
        "type": kind,
        "length": length,
    }})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_bounded_correlated_redacted_events() {
        let context = TraceContext::from_header_fn(|name| match name {
            "x-reproit-trace" => Some("trace-a".into()),
            "x-reproit-actor" => Some("alice".into()),
            "x-reproit-action" => Some("7".into()),
            _ => None,
        })
        .unwrap();
        let mut trace = BackendTrace::begin(
            context,
            "createProject",
            None,
            Some("org-1".into()),
            Some("retry-secret"),
            json!({"name":"demo","password":"abcdefgh"}),
            vec![Selection::new("project.id", "projectId").unwrap()],
        )
        .unwrap();
        trace
            .effect(
                EffectKind::Write,
                Some("projects"),
                Some("1"),
                Some("org-1"),
                None,
                None,
            )
            .unwrap();
        trace
            .finish(
                json!({
                    "id":1,
                    "apiKey":"sk_live_secret",
                    "publishable_key":"pk_live_secret",
                    "private-key":"private-secret",
                    "access key":"access-secret",
                    "signingKey":"signing-secret",
                    "monkey":"harmless"
                }),
                201,
                true,
                true,
            )
            .unwrap();
        assert!(trace.header().unwrap().len() < MAX_HEADER_BYTES);
        assert_eq!(trace.events()[0]["actionIndex"], 7);
        assert_eq!(
            trace.events()[0]["input"]["password"]["$reproit"]["length"],
            8
        );
        assert_ne!(trace.events()[0]["idempotencyKey"], "retry-secret");
        assert_eq!(
            trace.events()[2]["output"]["apiKey"]["$reproit"]["redacted"],
            true
        );
        assert_eq!(
            trace.events()[2]["output"]["publishable_key"]["$reproit"]["redacted"],
            true
        );
        for field in ["private-key", "access key", "signingKey"] {
            assert_eq!(
                trace.events()[2]["output"][field]["$reproit"]["redacted"],
                true
            );
        }
        assert_eq!(trace.events()[2]["output"]["monkey"], "harmless");
        assert_eq!(trace.events()[2]["effectsComplete"], true);
    }

    #[test]
    fn stays_inactive_without_a_trace_header() {
        assert!(TraceContext::from_header_fn(|_| None).is_none());
    }

    #[test]
    fn canonical_http_input_lowercases_headers_and_preserves_repeated_values() {
        let input = HttpInput {
            body: Some(json!({"name":"demo"})),
            path: BTreeMap::from([("project".into(), json!("p1"))]),
            query: BTreeMap::from([("tag".into(), json!(["a", "b"]))]),
            headers: BTreeMap::from([("X-Mode".into(), json!("safe"))]),
        }
        .into_value();
        assert_eq!(input["headers"]["x-mode"], "safe");
        assert_eq!(input["query"]["tag"], json!(["a", "b"]));
    }
}
