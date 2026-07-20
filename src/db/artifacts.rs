//! Atomic persistence for validated, content-addressed evidence graphs.

use super::tenant::TenantStore;
use reproit_protocol::EvidenceGraph;
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};

impl TenantStore {
    pub async fn proof_ledger(
        &self,
        app_id: &str,
        run_id: &str,
    ) -> anyhow::Result<Option<(String, reproit_protocol::ProofLedger)>> {
        let row = sqlx::query(
            "SELECT roots.root_id, nodes.payload
             FROM artifact_roots roots
             JOIN artifact_nodes nodes
               ON nodes.app_id = roots.app_id AND nodes.node_id = roots.root_id
             WHERE roots.app_id = $1 AND roots.run_id = $2 AND nodes.kind = 'proof-ledger'
             ORDER BY roots.created_at DESC, roots.root_id
             LIMIT 1",
        )
        .bind(app_id)
        .bind(run_id)
        .fetch_optional(self.pool.as_ref())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let root: String = row.try_get("root_id")?;
        let payload: Value = row.try_get("payload")?;
        let ledger: reproit_protocol::ProofLedger = serde_json::from_value(payload)?;
        ledger.validate()?;
        Ok(Some((root, ledger)))
    }
}

pub(super) async fn store_graphs(
    transaction: &mut Transaction<'_, Postgres>,
    app_id: &str,
    evidence: &[EvidenceGraph],
) -> anyhow::Result<()> {
    let mut unique_nodes = std::collections::BTreeMap::new();
    for node in evidence.iter().flat_map(|graph| &graph.nodes) {
        unique_nodes.entry(node.id.as_str()).or_insert(node);
    }
    let nodes = unique_nodes.into_values().collect::<Vec<_>>();
    if nodes.is_empty() {
        return Ok(());
    }

    let ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<Vec<_>>();
    let kinds = nodes
        .iter()
        .map(|node| node.kind.as_str())
        .collect::<Vec<_>>();
    let parents = nodes
        .iter()
        .map(|node| serde_json::to_value(&node.parents).unwrap_or(Value::Null))
        .collect::<Vec<_>>();
    let payloads = nodes
        .iter()
        .map(|node| node.payload.clone())
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO artifact_nodes (app_id, node_id, kind, parents, payload)
         SELECT $1, n, k, p, v
         FROM UNNEST($2::text[], $3::text[], $4::jsonb[], $5::jsonb[]) AS t(n, k, p, v)
         ON CONFLICT (app_id, node_id) DO NOTHING",
    )
    .bind(app_id)
    .bind(&ids)
    .bind(&kinds)
    .bind(&parents)
    .bind(&payloads)
    .execute(&mut **transaction)
    .await?;

    let run_ids = evidence
        .iter()
        .map(|graph| graph.run_id.as_str())
        .collect::<Vec<_>>();
    let root_ids = evidence
        .iter()
        .map(|graph| graph.root.as_str())
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO artifact_roots (app_id, run_id, root_id)
         SELECT $1, r, n FROM UNNEST($2::text[], $3::text[]) AS t(r, n)
         ON CONFLICT (app_id, run_id, root_id) DO NOTHING",
    )
    .bind(app_id)
    .bind(&run_ids)
    .bind(&root_ids)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
