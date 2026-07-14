//! Experimental trace-bound HTTP contract capture.
//!
//! This module is inert unless `REPROIT_EXPERIMENTAL_BACKEND_CONTRACTS=1` and
//! the individual request carries `x-reproit-trace`. It is deliberately scoped
//! to the five dogfooded JSON operations in `openapi()`.

use axum::body::{to_bytes, Body};
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use reproit_backend::{BackendTrace, TraceContext};
use serde_json::{json, Map, Value};

#[derive(Clone, Copy)]
struct Endpoint {
    method: &'static str,
    router_path: &'static str,
    openapi_path: &'static str,
    operation: &'static str,
}

const ENDPOINTS: [Endpoint; 5] = [
    Endpoint {
        method: "post",
        router_path: "/auth/signup",
        openapi_path: "/auth/signup",
        operation: "cloudSignup",
    },
    Endpoint {
        method: "post",
        router_path: "/account/projects",
        openapi_path: "/account/projects",
        operation: "cloudCreateProject",
    },
    Endpoint {
        method: "post",
        router_path: "/v1/events",
        openapi_path: "/v1/events",
        operation: "cloudIngestEvents",
    },
    Endpoint {
        method: "get",
        router_path: "/v1/me",
        openapi_path: "/v1/me",
        operation: "cloudGetMe",
    },
    Endpoint {
        method: "post",
        router_path: "/v1/apps/:app/buckets/:bucket/replay-results",
        openapi_path: "/v1/apps/{app}/buckets/{bucket}/replay-results",
        operation: "cloudRecordReplay",
    },
];

// Router registration aliases are derived from the same registry that drives
// trace operation matching and schema parity tests.
pub const SIGNUP: &str = ENDPOINTS[0].router_path;
pub const CREATE_PROJECT: &str = ENDPOINTS[1].router_path;
pub const INGEST_EVENTS: &str = ENDPOINTS[2].router_path;
pub const GET_ME: &str = ENDPOINTS[3].router_path;
pub const RECORD_REPLAY: &str = ENDPOINTS[4].router_path;

pub fn enabled() -> bool {
    std::env::var("REPROIT_EXPERIMENTAL_BACKEND_CONTRACTS").as_deref() == Ok("1")
}

pub fn openapi() -> Value {
    let document = serde_json::from_str(include_str!("../contracts/backend-openapi.json"))
        .expect("checked-in backend contract must be valid JSON");
    assert!(
        registry_matches(&document),
        "checked-in backend contract drifted from the route registry"
    );
    document
}

fn registry_matches(schema: &Value) -> bool {
    ENDPOINTS.iter().all(|endpoint| {
        schema
            .pointer(&format!(
                "/paths/{}/{}",
                endpoint.openapi_path.replace('~', "~0").replace('/', "~1"),
                endpoint.method,
            ))
            .and_then(|operation| operation.get("operationId"))
            .and_then(Value::as_str)
            == Some(endpoint.operation)
    })
}

pub async fn capture(request: Request, next: Next) -> Response {
    let context = TraceContext::from_header_fn(|name| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    });
    let Some(context) = context else {
        return next.run(request).await;
    };
    let Some((operation, path_values)) = operation(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 32 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return Response::builder().status(413).body(Body::empty()).unwrap(),
    };
    let parsed = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    let input = if path_values.is_empty() {
        parsed
    } else {
        json!({"body":parsed,"path":path_values})
    };
    let Ok(mut trace) =
        BackendTrace::begin(context, operation, None, None, None, input, Vec::new())
    else {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };
    let request = Request::from_parts(parts, Body::from(bytes));
    let response = next.run(request).await;
    let status = response.status();
    let (mut parts, body) = response.into_parts();
    let bytes = match to_bytes(body, 4 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return Response::from_parts(parts, Body::empty()),
    };
    let output = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
    let _ = trace.finish(
        output,
        status.as_u16(),
        status.is_success() || status.is_redirection(),
        false,
    );
    if let Ok(encoded) = trace.header() {
        parts.headers.insert(
            HeaderName::from_static("x-reproit-events"),
            HeaderValue::from_str(&encoded).expect("base64url header"),
        );
    }
    Response::from_parts(parts, Body::from(bytes))
}

fn operation(method: &Method, path: &str) -> Option<(&'static str, Map<String, Value>)> {
    let empty = || Map::new();
    if let Some(endpoint) = ENDPOINTS[..4].iter().find(|endpoint| {
        method.as_str().eq_ignore_ascii_case(endpoint.method) && path == endpoint.router_path
    }) {
        return Some((endpoint.operation, empty()));
    }
    match (method, path) {
        (&Method::POST, _) => {
            let parts = path.trim_matches('/').split('/').collect::<Vec<_>>();
            (parts.len() == 6
                && parts[0] == "v1"
                && parts[1] == "apps"
                && parts[3] == "buckets"
                && parts[5] == "replay-results")
                .then(|| {
                    (
                        ENDPOINTS[4].operation,
                        Map::from_iter([
                            ("app".into(), json!(parts[2])),
                            ("bucket".into(), json!(parts[4])),
                        ]),
                    )
                })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_and_schema_are_one_source() {
        let schema = openapi();
        assert!(registry_matches(&schema));
        assert_eq!(
            operation(&Method::POST, "/v1/apps/app-a/buckets/bkt-a/replay-results")
                .map(|(operation, _)| operation),
            Some(ENDPOINTS[4].operation),
        );
    }
}
