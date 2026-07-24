//! One-shot tenant administration and retention operations.

use super::*;

/// Offboard one tenant end to end (the Cmd::Offboard body): data plane first
/// (database at the provider, blobs under the scope), control plane last, so a
/// crash mid-way leaves a re-runnable half (the command is idempotent).
pub(super) async fn run_offboard(
    app: &App,
    blobs: &tenancy::blob::Blobs,
    org_id: i64,
    yes: bool,
) -> anyhow::Result<()> {
    if !yes {
        anyhow::bail!(
            "offboard permanently deletes org {org_id}'s database, blobs, keys and members; re-run with --yes to confirm"
        );
    }
    if app.self_hosted {
        anyhow::bail!(
            "offboard is a hosted (multi-tenant) operation; self-host owns its one database"
        );
    }
    let scope = app
        .control
        .all_tenants()
        .await?
        .into_iter()
        .find(|t| t.org_id == org_id)
        .map(|t| t.blob_scope)
        .unwrap_or_else(|| format!("t/{org_id}"));
    app.tenancy.deprovision(org_id).await?;
    tracing::info!("offboard: org {org_id} database deprovisioned");
    match blobs.delete_scope(&scope).await {
        Ok(n) => tracing::info!("offboard: blob scope {scope} cleared ({n} object(s)/tree)"),
        Err(e) => {
            tracing::warn!("offboard: blob scope {scope} cleanup failed (re-run to retry): {e}")
        }
    }
    let deleted = app.control.delete_org(org_id).await?;
    app.control
        .audit(
            "ops",
            "org.offboard",
            Some(org_id),
            serde_json::json!({ "deleted": deleted }),
        )
        .await;
    tracing::info!("offboard: org {org_id} removed from the control plane (existed: {deleted})");
    Ok(())
}

/// Suspend or resume one tenant (Cmd::Suspend / Cmd::Resume): flip the registry
/// status the resolver serves by. Suspension is reversible (database and blobs
/// intact), but it takes the tenant's ingest and dashboard down, so it demands
/// --yes; resume never does. Audited like every ops action.
pub(super) async fn run_set_tenant_status(
    app: &App,
    org_id: i64,
    status: db::TenantStatus,
    yes: bool,
) -> anyhow::Result<()> {
    let verb = match status {
        db::TenantStatus::Suspended => "suspend",
        _ => "resume",
    };
    if status == db::TenantStatus::Suspended && !yes {
        anyhow::bail!(
            "suspend takes org {org_id} out of service (ingest + dashboard refuse) until `resume`; re-run with --yes to confirm"
        );
    }
    let Some(current) = app.control.tenant(org_id).await? else {
        anyhow::bail!("org {org_id} has no tenant record; nothing to {verb}");
    };
    if current.status == status {
        tracing::info!("{verb}: org {org_id} is already {}", status.as_str());
        return Ok(());
    }
    app.control.set_tenant_status(org_id, status).await?;
    // The resolver caches mappings briefly (TTL backstop), so the flip takes
    // effect within the cache window on running instances; audit the change.
    app.control
        .audit(
            "ops",
            match status {
                db::TenantStatus::Suspended => "org.suspend",
                _ => "org.resume",
            },
            Some(org_id),
            serde_json::json!({ "from": current.status.as_str(), "to": status.as_str() }),
        )
        .await;
    tracing::info!(
        "{verb}: org {org_id} {} -> {}",
        current.status.as_str(),
        status.as_str()
    );
    Ok(())
}

/// List every tenant in the registry (Cmd::Tenants) as an aligned table: the
/// ops "what is this fleet" read. Name and plan live on `orgs`; a tenant row
/// whose org is gone prints a placeholder rather than erroring the whole list.
pub(super) async fn run_list_tenants(app: &App) -> anyhow::Result<()> {
    let tenants = app.control.all_tenants().await?;
    let mut rows: Vec<[String; 4]> = Vec::with_capacity(tenants.len());
    for t in &tenants {
        let (name, plan) = app
            .control
            .org_name_plan(t.org_id)
            .await?
            .unwrap_or_else(|| ("<no org row>".to_string(), "-".to_string()));
        rows.push([
            t.org_id.to_string(),
            name,
            t.status.as_str().to_string(),
            plan,
        ]);
    }
    app.control
        .audit(
            "ops",
            "ops.tenants",
            None,
            serde_json::json!({ "count": rows.len() }),
        )
        .await;
    print_table(["ORG", "NAME", "STATUS", "PLAN"], &rows);
    Ok(())
}

/// Print an aligned four-column table (header + rows) for the ops subcommands.
/// Plain spaces-and-padding, no table crate: the output is for a human at a
/// terminal and for `grep`, nothing else.
pub(super) fn print_table(header: [&str; 4], rows: &[[String; 4]]) {
    let mut w = header.map(str::len);
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            w[i] = w[i].max(cell.len());
        }
    }
    println!(
        "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}",
        header[0],
        header[1],
        header[2],
        header[3],
        w0 = w[0],
        w1 = w[1],
        w2 = w[2],
        w3 = w[3]
    );
    for row in rows {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {:<w3$}",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = w[0],
            w1 = w[1],
            w2 = w[2],
            w3 = w[3]
        );
    }
}

/// Print an org's recent audit rows, newest first (Cmd::Audit). The read query
/// this drives (`audit_for_org`) is the audit table's first reader; until now
/// it was write-only and inspectable only via psql.
pub(super) async fn run_audit(app: &App, org_id: i64, limit: i64) -> anyhow::Result<()> {
    let rows = app.control.audit_for_org(org_id, limit.max(1)).await?;
    // Reading the trail is itself an admin action worth a trace (matches the
    // admin-key HTTP surface, where even reads are audited).
    app.control
        .audit(
            "ops",
            "org.audit_read",
            Some(org_id),
            serde_json::json!({ "limit": limit, "returned": rows.len() }),
        )
        .await;
    if rows.is_empty() {
        println!("no audit rows for org {org_id}");
        return Ok(());
    }
    for r in &rows {
        println!("{}  {:<12}  {:<24}  {}", r.at, r.actor, r.action, r.detail);
    }
    Ok(())
}

/// Requeue one tenant's stranded shards on demand (Cmd::Requeue): the same
/// logic the minutely background sweep runs (stale threshold included), for
/// when ops shouldn't wait for the next tick. Re-marks the control-plane
/// pending hint exactly like the sweep does, so requeued shards are claimable
/// immediately (the under-inclusion invariant on `tenant_pending_shards`).
pub(super) async fn run_requeue(app: &App, org_id: i64) -> anyhow::Result<()> {
    let tenant = app
        .tenancy
        .resolve(org_id)
        .await
        .map_err(|e| anyhow::anyhow!("cannot resolve tenant {org_id}: {e}"))?;
    let n = tenant.store.requeue_stranded(120).await?;
    if n >= 1 {
        app.control.mark_tenant_pending(org_id).await?;
    }
    app.control
        .audit(
            "ops",
            "org.requeue",
            Some(org_id),
            serde_json::json!({ "requeued": n }),
        )
        .await;
    tracing::info!("requeue: org {org_id} requeued {n} stranded shard(s)");
    Ok(())
}

/// One tenant's retention pass: delete evidence BLOBS for errors past the
/// plan's retention window, then their rows, then the error rows themselves
/// (evidence-first so a crash can only leave re-processable rows behind, never
/// orphaned customer bytes in object storage). Batched; errors are logged and
/// retried on the next hourly pass.
#[allow(dead_code)] // Driven by the hosted retention loop; self-host owns retention.
pub(super) async fn retention_pass(tenant: &tenancy::resolver::Tenant, org_id: i64, days: i64) {
    let mut blobs_deleted = 0u64;
    loop {
        let batch = match tenant.store.expired_evidence_keys(days, 500).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("retention: expired_evidence_keys for tenant {org_id}: {e}");
                return;
            }
        };
        if batch.is_empty() {
            break;
        }
        let n = batch.len();
        let mut deletable = Vec::with_capacity(n);
        for (id, key) in batch {
            match tenant.blobs.delete(&key).await {
                Ok(()) => deletable.push(id),
                // Keep the row so the next pass retries this blob.
                Err(e) => tracing::warn!("retention: blob delete {key} for tenant {org_id}: {e}"),
            }
        }
        blobs_deleted += deletable.len() as u64;
        if let Err(e) = tenant.store.delete_evidence_rows(&deletable).await {
            tracing::warn!("retention: delete_evidence_rows for tenant {org_id}: {e}");
            return;
        }
        if deletable.is_empty() || n < 500 {
            break;
        }
    }
    let mut errors_deleted = 0u64;
    loop {
        match tenant.store.delete_expired_errors(days, 5000).await {
            Ok(n) => {
                errors_deleted += n;
                if n < 5000 {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("retention: delete_expired_errors for tenant {org_id}: {e}");
                return;
            }
        }
    }
    if blobs_deleted > 0 || errors_deleted > 0 {
        tracing::info!(
            "retention: tenant {org_id} pruned {errors_deleted} error(s), {blobs_deleted} evidence blob(s) past {days}d"
        );
    }
}

/// Apply the tenant schema to every ACTIVE tenant database, `concurrency` at a
/// time. Failures are collected, never short-circuited, so one broken tenant
/// cannot hide the rest of the fleet's result.
pub(super) async fn run_tenant_migrations(app: &App, concurrency: usize) -> anyhow::Result<()> {
    let tenants = app.control.all_tenants().await?;
    let mut pending = tokio::task::JoinSet::new();
    let mut failures = Vec::new();
    let mut migrated = 0usize;
    for tenant in tenants {
        if tenant.status != db::TenantStatus::Active {
            continue;
        }
        let Some(conn) = tenant.db_conn else { continue };
        while pending.len() >= concurrency {
            let result = pending
                .join_next()
                .await
                .expect("migration task exists")??;
            migrated += 1;
            if let Some(failure) = result {
                failures.push(failure);
            }
        }
        pending.spawn(async move {
            Ok::<_, anyhow::Error>(
                db::schema::apply(&conn)
                    .await
                    .err()
                    .map(|error| format!("tenant {}: {error}", tenant.org_id)),
            )
        });
    }
    while let Some(result) = pending.join_next().await {
        migrated += 1;
        if let Some(failure) = result?? {
            failures.push(failure);
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "{} of {migrated} tenant migrations failed: {}",
            failures.len(),
            failures.join("; ")
        );
    }
    tracing::info!("migrated {migrated} active tenant database(s)");
    Ok(())
}
