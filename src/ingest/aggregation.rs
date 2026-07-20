//! Pure reduction of validated protocol frames into persistence inputs.

use super::{ErrorRec, Step};
use reproit_protocol::{Event, EventFrame};
use serde_json::{Map, Value};

pub(super) struct BatchAgg {
    pub(super) edge_counts: std::collections::HashMap<String, i64>,
    pub(super) error_recs: Vec<ErrorRec>,
}

pub(super) fn aggregate_events(frames: &[EventFrame]) -> BatchAgg {
    let mut edge_counts = std::collections::HashMap::new();
    let mut error_recs = Vec::new();
    for frame in frames {
        match &frame.event {
            Event::GraphEdge { from, action, to } => {
                let key = format!("{from}|{action}|{to}");
                *edge_counts.entry(key).or_insert(0) += 1;
            }
            Event::Finding {
                signature,
                message,
                identity,
                path,
                context,
            } => {
                let mut stored_context: Map<String, Value> = context.clone().into_iter().collect();
                stored_context.insert(
                    "findingIdentity".into(),
                    serde_json::to_value(identity).expect("typed identity serializes"),
                );
                stored_context.insert("oracle".into(), Value::String(identity.oracle.clone()));
                error_recs.push(ErrorRec {
                    sig: signature.clone(),
                    message: message.clone(),
                    path: path
                        .iter()
                        .map(|step| Step {
                            sig: step.signature.clone(),
                            action: step.action.clone(),
                            label: step.label.clone(),
                        })
                        .collect(),
                    context: stored_context,
                });
            }
            Event::Action { .. }
            | Event::Observation { .. }
            | Event::Backend { .. }
            | Event::StreamDefect { .. } => {}
        }
    }
    BatchAgg {
        edge_counts,
        error_recs,
    }
}
