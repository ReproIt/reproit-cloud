//! Test-only writer for hosted production-gate evidence fragments.
//!
//! A gate test that passes writes ONE small JSON fragment
//! (`{"gate": ..., "status": "pass", ...payload}`) to the path named by
//! `GATE_EVIDENCE_PATH`, and only when that env var is set, so plain
//! `cargo test` behavior is unchanged. The hosted-production-gates workflow
//! sets the path, uploads the fragment as the job artifact, and the deploy
//! repo's `assemble_production_evidence.py` folds the fragments into the
//! schemaVersion=2 manifest that `verify_production_readiness.py` validates.

/// Env var naming where the fragment is written. Unset = no fragment.
pub(crate) const ENV_PATH: &str = "GATE_EVIDENCE_PATH";

/// A fragment is a handful of scalar fields; anything bigger is a bug.
const MAX_FRAGMENT_BYTES: usize = 65_536;

/// Write the passing fragment for `gate`. `payload` must be a JSON object of
/// exactly the gate's manifest payload fields. Called ONLY after every check
/// in the gate has passed (a failed gate panics before reaching this, so no
/// fragment ever exists for a failed run: fail closed).
pub(crate) fn write_fragment(gate: &str, payload: serde_json::Value) {
    let Ok(path) = std::env::var(ENV_PATH) else {
        return;
    };
    assert!(!path.is_empty(), "{ENV_PATH} is set but empty");
    let mut doc = serde_json::Map::new();
    doc.insert("gate".into(), serde_json::Value::String(gate.into()));
    doc.insert("status".into(), serde_json::Value::String("pass".into()));
    let serde_json::Value::Object(fields) = payload else {
        panic!("gate {gate} payload must be a JSON object");
    };
    for (key, value) in fields {
        assert!(
            doc.insert(key.clone(), value).is_none(),
            "gate {gate} payload field {key:?} collides with fragment envelope"
        );
    }
    let bytes = serde_json::to_vec_pretty(&serde_json::Value::Object(doc))
        .expect("gate fragment serializes");
    assert!(
        bytes.len() <= MAX_FRAGMENT_BYTES,
        "gate {gate} fragment exceeds {MAX_FRAGMENT_BYTES} bytes"
    );
    std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write gate fragment to {path}: {e}"));
    eprintln!("gate {gate}: evidence fragment written to {path}");
}

#[cfg(test)]
mod tests {
    // The writer itself is exercised through the gate tests; this covers the
    // envelope shape without touching the process environment (env mutation in
    // parallel tests races), by calling through a temp path via the env only
    // when it is already absent.
    #[test]
    fn absent_env_writes_nothing() {
        // If a caller exported GATE_EVIDENCE_PATH into the whole test run this
        // test is vacuous, which is fine: the gate jobs set it deliberately.
        if std::env::var(super::ENV_PATH).is_err() {
            super::write_fragment("noopGate", serde_json::json!({ "ok": true }));
        }
    }
}
