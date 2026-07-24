//! Process argument surface: the server flags and the one-shot ops
//! subcommands. Split from lib.rs so composition stays under the file cap.

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "reproit-cloud",
    version = env!("CARGO_PKG_VERSION"),
    about = "ReproIt cloud control plane"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) cmd: Option<Cmd>,
    #[arg(long, default_value_t = 8080)]
    pub(crate) port: u16,
    /// Embedded worker pool size (local dev: the control plane also claims and
    /// runs shards itself). In production this is 0 and remote workers claim.
    #[arg(long, default_value_t = 0)]
    pub(crate) workers: usize,
    /// Path to the reproit binary the (embedded) workers invoke.
    #[arg(long, default_value = "reproit")]
    pub(crate) reproit_bin: String,
}

/// The one-shot subcommand surface (ops).
#[derive(clap::Subcommand)]
pub(crate) enum Cmd {
    /// Print the experimental route-registry-checked backend contract and exit.
    #[command(hide = true)]
    BackendContract,
    /// Offboard a tenant COMPLETELY (ops/GDPR): tear down its database at the
    /// provider, delete every blob under its scope, and remove the org (members,
    /// keys, tenants row, usage cascade). Refuses to run without --yes.
    Offboard {
        /// The org id to offboard.
        #[arg(long)]
        org: i64,
        /// Confirm the irreversible deletion.
        #[arg(long)]
        yes: bool,
    },
    /// Suspend a tenant (ops: billing/abuse): the resolver stops serving it, so
    /// ingest and the dashboard refuse, but its database and blobs stay intact.
    /// Reversible with `resume`. Refuses to run without --yes.
    Suspend {
        /// The org id to suspend.
        org: i64,
        /// Confirm taking the tenant out of service.
        #[arg(long)]
        yes: bool,
    },
    /// Resume a suspended tenant (status back to active; served again).
    Resume {
        /// The org id to resume.
        org: i64,
    },
    /// List every tenant in the registry as a table: org id, name, status, plan.
    Tenants,
    /// Print an org's most recent audit-log rows, newest first.
    Audit {
        /// The org id to read the audit trail for.
        org: i64,
        /// How many rows to print.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Requeue one tenant's stranded shards now (the background sweep does this
    /// every minute; this is the on-demand ops form).
    Requeue {
        /// The org id whose queue to requeue.
        org: i64,
    },
    /// Self-host install bootstrap: create the single org, an admin owner, and a
    /// default project + its first API key (printed once), then exit. Idempotent:
    /// safe to re-run (it never mints a second key). Resolves the single-tenant DB
    /// from DATABASE_URL / REPROIT_SELF_HOSTED_DB exactly like self-host startup.
    Init {
        /// Admin account email (becomes owner of the single org).
        #[arg(long)]
        email: String,
        /// Admin account password (at least 8 characters).
        #[arg(long)]
        password: String,
        /// Name of the default project to create.
        #[arg(long, default_value = "Default")]
        project: String,
    },
}
