//! Bounded causal-event DAG shared by local and hosted proof consumers.

use crate::{validate_text, validate_token, ProtocolError, ReasonCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const CAUSAL_GRAPH_VERSION: u16 = 1;
pub const MAX_CAUSAL_NODES: usize = 16_384;
pub const MAX_CAUSAL_EDGES: usize = 65_536;
const MAX_CAUSAL_LABEL_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CausalNodeKind {
    Action,
    Response,
    Timer,
    StateWrite,
    Callback,
    Permission,
    ActorEvent,
    BackendEvent,
    Environment,
    Finding,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CausalTarget {
    Action {
        actor: String,
        index: u32,
    },
    Exchange {
        actor: String,
        action_index: u32,
        ordinal: u32,
        exchange_id: String,
    },
    BackendEvent {
        sequence: u64,
        trace_id: String,
        span_id: String,
    },
    Environment {
        key: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalNode {
    pub id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<CausalTarget>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CausalEdgeKind {
    HappensBefore,
    DataDependency,
    StatePrerequisite,
    ActorOwnership,
    ContractScope,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalEdge {
    pub from: String,
    pub to: String,
    pub kind: CausalEdgeKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalGraph {
    pub version: u16,
    pub nodes: Vec<CausalNode>,
    pub edges: Vec<CausalEdge>,
}

impl Default for CausalGraph {
    fn default() -> Self {
        Self {
            version: CAUSAL_GRAPH_VERSION,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }
}

impl CausalGraph {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != CAUSAL_GRAPH_VERSION {
            return Err(ProtocolError::new(ReasonCode::UnsupportedVersion));
        }
        if self.nodes.len() > MAX_CAUSAL_NODES || self.edges.len() > MAX_CAUSAL_EDGES {
            return Err(ProtocolError::new(ReasonCode::BatchTooLarge));
        }
        let mut ids = BTreeSet::new();
        for node in &self.nodes {
            validate_node(node)?;
            if !ids.insert(node.id.clone()) {
                return Err(ProtocolError::new(ReasonCode::InvalidEvent));
            }
        }
        let mut indegree = ids
            .iter()
            .map(|id| (id.clone(), 0usize))
            .collect::<BTreeMap<_, _>>();
        let mut outgoing: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut unique_edges = BTreeSet::new();
        for edge in &self.edges {
            validate_token(&edge.from)?;
            validate_token(&edge.to)?;
            if edge.from == edge.to
                || !ids.contains(&edge.from)
                || !ids.contains(&edge.to)
                || !unique_edges.insert(edge)
            {
                return Err(ProtocolError::new(ReasonCode::InvalidEvent));
            }
            *indegree.get_mut(&edge.to).expect("checked endpoint") += 1;
            outgoing.entry(&edge.from).or_default().push(&edge.to);
        }
        let mut ready = indegree
            .iter()
            .filter(|(_, degree)| **degree == 0)
            .map(|(id, _)| id.clone())
            .collect::<VecDeque<_>>();
        let mut visited = 0usize;
        while let Some(id) = ready.pop_front() {
            visited += 1;
            for next in outgoing.get(id.as_str()).into_iter().flatten() {
                let degree = indegree.get_mut(*next).expect("checked endpoint");
                *degree -= 1;
                if *degree == 0 {
                    ready.push_back((*next).to_string());
                }
            }
        }
        if visited != self.nodes.len() {
            return Err(ProtocolError::new(ReasonCode::InvalidSequence));
        }
        Ok(())
    }

    pub fn reduction_nodes(&self) -> Vec<String> {
        self.nodes
            .iter()
            .filter(|node| {
                matches!(
                    node.target,
                    Some(CausalTarget::Action { .. })
                        | Some(CausalTarget::Exchange { .. })
                        | Some(CausalTarget::BackendEvent { .. })
                )
            })
            .map(|node| node.id.clone())
            .collect()
    }

    pub fn removal_closure(&self, requested: &BTreeSet<String>) -> BTreeSet<String> {
        let mut removed = requested.clone();
        let mut pending = requested.iter().cloned().collect::<VecDeque<_>>();
        while let Some(id) = pending.pop_front() {
            for edge in self.edges.iter().filter(|edge| {
                edge.from == id
                    && matches!(
                        edge.kind,
                        CausalEdgeKind::DataDependency | CausalEdgeKind::StatePrerequisite
                    )
            }) {
                if removed.insert(edge.to.clone()) {
                    pending.push_back(edge.to.clone());
                }
            }
        }
        removed
    }
}

fn validate_node(node: &CausalNode) -> Result<(), ProtocolError> {
    validate_token(&node.id)?;
    validate_text(&node.label, MAX_CAUSAL_LABEL_BYTES)?;
    node.actor.as_deref().map(validate_token).transpose()?;
    let valid_target = matches!(
        (&node.kind, &node.target),
        (CausalNodeKind::Action, Some(CausalTarget::Action { .. }))
            | (
                CausalNodeKind::Response,
                Some(CausalTarget::Exchange { .. })
            )
            | (
                CausalNodeKind::Timer | CausalNodeKind::Permission | CausalNodeKind::Environment,
                Some(CausalTarget::Environment { .. })
            )
            | (
                CausalNodeKind::StateWrite,
                None | Some(CausalTarget::BackendEvent { .. })
            )
            | (
                CausalNodeKind::Callback | CausalNodeKind::BackendEvent,
                Some(CausalTarget::BackendEvent { .. })
            )
            | (CausalNodeKind::ActorEvent | CausalNodeKind::Finding, None)
    );
    if !valid_target {
        return Err(ProtocolError::new(ReasonCode::InvalidEvent));
    }
    match &node.target {
        Some(CausalTarget::Action { actor, .. }) => validate_token(actor),
        Some(CausalTarget::Exchange {
            actor, exchange_id, ..
        }) => {
            validate_token(actor)?;
            validate_text(exchange_id, MAX_CAUSAL_LABEL_BYTES)
        }
        Some(CausalTarget::BackendEvent {
            trace_id, span_id, ..
        }) => {
            validate_token(trace_id)?;
            validate_token(span_id)
        }
        Some(CausalTarget::Environment { key }) => validate_text(key, MAX_CAUSAL_LABEL_BYTES),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str) -> CausalNode {
        CausalNode {
            id: id.into(),
            kind: CausalNodeKind::ActorEvent,
            label: id.into(),
            actor: None,
            target: None,
        }
    }

    #[test]
    fn rejects_cycles() {
        let graph = CausalGraph {
            version: CAUSAL_GRAPH_VERSION,
            nodes: vec![node("a"), node("b")],
            edges: vec![
                CausalEdge {
                    from: "a".into(),
                    to: "b".into(),
                    kind: CausalEdgeKind::HappensBefore,
                },
                CausalEdge {
                    from: "b".into(),
                    to: "a".into(),
                    kind: CausalEdgeKind::DataDependency,
                },
            ],
        };

        assert_eq!(
            graph.validate().unwrap_err().reason,
            ReasonCode::InvalidSequence
        );
    }

    #[test]
    fn dependency_closure_does_not_follow_ordering_edges() {
        let graph = CausalGraph {
            version: CAUSAL_GRAPH_VERSION,
            nodes: vec![node("action"), node("response"), node("later")],
            edges: vec![
                CausalEdge {
                    from: "action".into(),
                    to: "response".into(),
                    kind: CausalEdgeKind::DataDependency,
                },
                CausalEdge {
                    from: "response".into(),
                    to: "later".into(),
                    kind: CausalEdgeKind::HappensBefore,
                },
            ],
        };

        assert_eq!(
            graph.removal_closure(&BTreeSet::from(["action".into()])),
            BTreeSet::from(["action".into(), "response".into()])
        );
    }
}
