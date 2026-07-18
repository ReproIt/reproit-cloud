//! Pure reduction of SDK event batches into bounded persistence inputs.

use super::*;

/// The oracle gate for POST /v1/events: an error may open a bucket ONLY if it
/// carries a well-formed oracle id. The check is PRESENCE + WELL-FORMEDNESS, NOT
/// registry membership -- a well-formed but unrecognized id can come from a newer
/// CLI/SDK than this cloud build, and the registry contract says consumers must
/// degrade gracefully on an unknown id rather than drop a finding, so it passes.
/// A missing, empty, over-length, or non-token id is rejected. Well-formed is a
/// bounded lowercase token: ascii a-z, 0-9, '-' and '_' (registry ids such as
/// `choice-anomaly` pass; uppercase, spaces, and other punctuation do not).
/// Uncaught crashes reach here as oracle:"crash", so they pass the gate.
pub(super) fn oracle_well_formed(oracle: &str) -> bool {
    !oracle.is_empty()
        && oracle.len() <= MAX_ORACLE_ID_BYTES
        && oracle
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// One batch's events reduced to what the write needs: edge deltas summed by key,
/// the accepted error occurrences, and the count of error events the oracle gate
/// dropped (surfaced to the caller so an SDK emitting untagged errors sees it).
pub(super) struct BatchAgg {
    pub(super) edge_counts: std::collections::HashMap<String, i64>,
    pub(super) error_recs: Vec<ErrorRec>,
    pub(super) dropped_untagged: u64,
}

/// Scan a batch's events into edge deltas and gated error occurrences. Pure over
/// its inputs (no DB), so the oracle gate and in-batch edge summing stay
/// unit-testable without a tenant. Edge keys repeated within the batch are summed
/// here (the `edges` PK is (app_id, edge_key), so a multi-row upsert can touch
/// each row only once). Error events without a well-formed oracle id are gated
/// out before any ErrorRec forms and counted; only tagged findings become
/// buckets. `edge` and every other kind are unaffected by the gate.
pub(super) fn aggregate_events(events: &[Value], batch_ctx: &Map<String, Value>) -> BatchAgg {
    let mut edge_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut error_recs: Vec<ErrorRec> = Vec::new();
    let mut dropped_untagged: u64 = 0;
    for ev in events {
        match ev.get("kind").and_then(|v| v.as_str()) {
            Some("edge") => {
                let from = clipped(
                    ev.get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or("\u{2205}"),
                    MAX_STEP_FIELD_BYTES,
                );
                let action = clipped(
                    ev.get("action").and_then(|v| v.as_str()).unwrap_or("auto"),
                    MAX_STEP_FIELD_BYTES,
                );
                let to = clipped(
                    ev.get("to").and_then(|v| v.as_str()).unwrap_or("?"),
                    MAX_STEP_FIELD_BYTES,
                );
                let key = format!("{from}|{action}|{to}");
                *edge_counts.entry(key).or_insert(0) += 1;
            }
            Some("error") => {
                // Oracle gate: reject before building an ErrorRec so an untagged
                // or malformed finding never opens a bucket. Presence is the
                // `Some(..)` bind; well-formedness is the filter. See
                // oracle_well_formed for why an unknown-but-valid id passes.
                let Some(oracle) = ev
                    .get("oracle")
                    .and_then(|v| v.as_str())
                    .filter(|o| oracle_well_formed(o))
                else {
                    dropped_untagged += 1;
                    continue;
                };
                let sig = clipped(
                    ev.get("sig").and_then(|v| v.as_str()).unwrap_or("?"),
                    MAX_STEP_FIELD_BYTES,
                );
                let message = clipped(
                    ev.get("message").and_then(|v| v.as_str()).unwrap_or(""),
                    MAX_ERROR_MESSAGE_BYTES,
                );
                let path: Vec<Step> = ev
                    .get("path")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .take(MAX_PATH_STEPS)
                            .filter_map(|s| {
                                Some(Step {
                                    sig: clipped(s.get("sig")?.as_str()?, MAX_STEP_FIELD_BYTES),
                                    action: clipped(
                                        s.get("action")?.as_str()?,
                                        MAX_STEP_FIELD_BYTES,
                                    ),
                                    label: s
                                        .get("label")
                                        .and_then(|v| v.as_str())
                                        .filter(|s| !s.trim().is_empty())
                                        .map(|s| clipped(s.trim(), MAX_LABEL_BYTES)),
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut context = merge_context(batch_ctx, ev);
                // The SDK emits the same framework-neutral structural identity
                // the CLI writes beside a prelaunch finding. Preserve only a
                // fully typed, bounded object. Never trust a caller-supplied
                // `bugId`; the service recomputes it from these fields.
                let finding_identity = ev
                    .get("findingIdentity")
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<buckets::FindingIdentity>(value).ok()
                    })
                    .filter(|identity| {
                        [
                            identity.oracle.as_str(),
                            identity.invariant.as_str(),
                            identity.kind.as_str(),
                            identity.message.as_str(),
                            identity.frame.as_str(),
                            identity.trigger.as_str(),
                            identity.boundary.as_deref().unwrap_or(""),
                        ]
                        .iter()
                        .all(|field| field.len() <= MAX_STEP_FIELD_BYTES)
                    });
                // A context past the cap is dropped whole, leaving a marker: any
                // slice of it could mislead fixture synthesis downstream.
                if Value::Object(context.clone()).to_string().len() > MAX_CONTEXT_BYTES {
                    context = Map::new();
                    context.insert("reproitContextDropped".into(), Value::Bool(true));
                }
                if let Some(identity) = finding_identity {
                    context.insert("findingIdentity".into(), json!(identity));
                }
                // The structured oracle category the finding carried (crash /
                // security / blank-screen / ...), preserved for severity classifi-
                // cation on read. Stored AFTER the cap reset so this tiny, load-
                // bearing field always survives. The gate above guarantees it is
                // present and well-formed; clipped() is kept for uniform storage.
                // See impact::severity_for_oracle.
                context.insert(
                    "oracle".into(),
                    Value::String(clipped(oracle, MAX_STEP_FIELD_BYTES)),
                );
                error_recs.push(ErrorRec {
                    sig,
                    message,
                    path,
                    context,
                });
            }
            _ => {}
        }
    }
    BatchAgg {
        edge_counts,
        error_recs,
        dropped_untagged,
    }
}
