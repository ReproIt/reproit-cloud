//! Job + shard model. A fuzz job fans out into one shard per seed; each shard
//! is a unit of work for one worker. Persistence lives in db.rs (Postgres).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The allowed root that every job's `app_dir` MUST resolve under. A submitted
/// `app_dir` is canonicalized and confined here, so a caller cannot point the
/// worker at an arbitrary absolute path (e.g. `/etc`, another tenant's checkout)
/// and have the embedded `reproit` binary read its `reproit.yaml` / spawn against
/// it (finding #6).
///
/// `REPROIT_JOBS_ROOT` sets it explicitly (production: a dedicated checkout root).
/// Unset (self-host/dev), it defaults to the process's current working directory:
/// a sane, non-`/` base that keeps today's "run from your repo" workflow working
/// while still rejecting `../` escapes and absolute paths outside the repo.
pub fn jobs_root() -> PathBuf {
    match std::env::var_os("REPROIT_JOBS_ROOT") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

/// Canonicalize `app_dir` and confine it under [`jobs_root`]. Returns the
/// canonical path on success. Fails if the path does not exist, is not a
/// directory, or escapes the root (path traversal / absolute outside-root).
///
/// Canonicalization resolves `..` and symlinks first, so a symlink inside the
/// root that points outside is also rejected.
pub fn validate_app_dir(app_dir: &str) -> Result<PathBuf, String> {
    let root = jobs_root();
    // Canonicalize the root too: it may itself be a relative path or contain a
    // symlink, and we compare canonical-to-canonical.
    let root = root
        .canonicalize()
        .map_err(|e| format!("jobs root unavailable: {e}"))?;
    let candidate = Path::new(app_dir);
    let resolved = candidate
        .canonicalize()
        .map_err(|_| format!("app_dir does not exist or is not accessible: {app_dir}"))?;
    if !resolved.is_dir() {
        return Err(format!("app_dir is not a directory: {app_dir}"));
    }
    if !resolved.starts_with(&root) {
        return Err(format!("app_dir escapes the allowed jobs root: {app_dir}"));
    }
    Ok(resolved)
}

/// The worker side: claims shards off the durable queue + runs them (the HTTP
/// claim/heartbeat/result handlers + the optional embedded local-dev pool).
pub mod worker;

/// The scheduling policy the claim path orders by: which pending shard to hand a
/// worker, interactive-vs-batch headroom on the Mac tier, per-tenant lane caps,
/// pool sizing, and the autoscale signal. Pure + testable (see scheduler.rs).
pub mod scheduler;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobSpec {
    /// Absolute path to the app directory containing reproit.yaml.
    pub app_dir: String,
    /// "fuzz" (only mode in v0). Reserved for soak/journey jobs.
    #[serde(default = "default_mode")]
    #[allow(dead_code)]
    pub mode: String,
    /// Number of seeds = number of shards.
    #[serde(default = "default_seeds")]
    pub seeds: u32,
    /// Actions per walk.
    #[serde(default = "default_budget")]
    pub budget: u32,
    /// Device backend: web | android | ios. Determines which workers can claim
    /// the shards (a Linux worker advertises web/android; only a Mac claims ios).
    #[serde(default = "default_backend")]
    pub backend: String,
}

pub const MAX_JOB_SEEDS: u32 = 1_024;
pub const MAX_JOB_BUDGET: u32 = 10_000;

impl JobSpec {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_JOB_SEEDS).contains(&self.seeds) {
            return Err(format!("seeds must be between 1 and {MAX_JOB_SEEDS}"));
        }
        if !(1..=MAX_JOB_BUDGET).contains(&self.budget) {
            return Err(format!("budget must be between 1 and {MAX_JOB_BUDGET}"));
        }
        if !matches!(self.backend.as_str(), "web" | "android" | "ios") {
            return Err("backend must be one of: web, android, ios".into());
        }
        if self.mode != "fuzz" {
            return Err("mode must be fuzz".into());
        }
        Ok(())
    }
}

fn default_mode() -> String {
    "fuzz".into()
}
fn default_backend() -> String {
    "web".into()
}
fn default_seeds() -> u32 {
    8
}
fn default_budget() -> u32 {
    24
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ShardState {
    Pending,
    Running,
    Clean,
    Finding,
    Error,
}

impl ShardState {
    /// Stable lowercase tag stored in Postgres (matches the JSON serialization).
    pub fn as_str(&self) -> &'static str {
        match self {
            ShardState::Pending => "pending",
            ShardState::Running => "running",
            ShardState::Clean => "clean",
            ShardState::Finding => "finding",
            ShardState::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Shard {
    pub seed: u32,
    pub state: ShardState,
    /// Findings report (fuzz.md contents) when state == Finding.
    pub report: Option<String>,
    pub duration_s: f64,
}

pub struct Job {
    pub id: String,
    pub spec_app_dir: String,
    pub budget: u32,
    pub backend: String,
    pub shards: Vec<Shard>,
    pub started_at: String,
}

impl Job {
    pub fn new(spec: JobSpec) -> Self {
        let shards = (1..=spec.seeds)
            .map(|seed| Shard {
                seed,
                state: ShardState::Pending,
                report: None,
                duration_s: 0.0,
            })
            .collect();
        Job {
            id: uuid::Uuid::new_v4().to_string(),
            spec_app_dir: spec.app_dir,
            budget: spec.budget,
            backend: spec.backend,
            shards,
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `REPROIT_JOBS_ROOT` is process-global, so these env-mutating cases share a
    // lock and run as one #[test] to stay deterministic under the test harness.
    #[test]
    fn validate_app_dir_confines_to_the_jobs_root() {
        let root = std::env::temp_dir().join(format!("reproit-jobs-root-{}", uuid::Uuid::new_v4()));
        let inside = root.join("app");
        std::fs::create_dir_all(&inside).unwrap();
        // A sibling OUTSIDE the root (escape target).
        let outside =
            std::env::temp_dir().join(format!("reproit-outside-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&outside).unwrap();

        std::env::set_var("REPROIT_JOBS_ROOT", &root);

        // In-root directory: accepted, returns the canonical path under the root.
        let ok = validate_app_dir(inside.to_str().unwrap()).expect("in-root dir accepted");
        assert!(ok.starts_with(root.canonicalize().unwrap()));

        // Absolute path outside the root: rejected.
        let err = validate_app_dir(outside.to_str().unwrap()).unwrap_err();
        assert!(err.contains("escapes"), "got: {err}");

        // Traversal back out of the root: rejected (canonicalize resolves `..`).
        let escape = inside.join("../../etc");
        let _ = validate_app_dir(escape.to_str().unwrap()).unwrap_err();

        // Non-existent path: rejected as not-accessible, never silently allowed.
        let missing = root.join("does-not-exist");
        let err = validate_app_dir(missing.to_str().unwrap()).unwrap_err();
        assert!(err.contains("does not exist"), "got: {err}");

        std::env::remove_var("REPROIT_JOBS_ROOT");
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }
}
