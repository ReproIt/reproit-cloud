//! Cheap architecture ratchets for boundaries Rust does not encode itself.

use std::path::{Path, PathBuf};

fn rust_sources() -> Vec<PathBuf> {
    fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("read source directory") {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                collect(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    files.sort();
    files
}

#[test]
fn source_tree_uses_real_module_hierarchy() {
    for path in rust_sources() {
        let body = std::fs::read_to_string(&path).expect("read Rust source");
        assert!(
            !body.contains("#[path ="),
            "{} bypasses the module hierarchy with #[path]",
            path.display()
        );
    }
}

#[test]
fn source_files_stay_reviewable() {
    const MAX_LINES: usize = 1_000;
    for path in rust_sources() {
        let lines = std::fs::read_to_string(&path)
            .expect("read Rust source")
            .lines()
            .count();
        assert!(
            lines <= MAX_LINES,
            "{} has {lines} lines; split responsibilities before exceeding {MAX_LINES}",
            path.display()
        );
    }
}

#[test]
fn generic_catch_all_modules_are_not_added() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for name in ["common.rs", "crosscut.rs", "utils.rs"] {
        assert!(
            !src.join(name).exists(),
            "replace {name} with a domain module"
        );
    }
    for name in ["common", "crosscut", "utils"] {
        assert!(
            !src.join(name).is_dir(),
            "replace src/{name}/ with focused domain modules"
        );
    }
}

#[test]
fn architecture_standard_is_documented() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let guide = root.join("docs/architecture/code-organization.md");
    let body = std::fs::read_to_string(&guide).expect("read Cloud architecture guide");
    for rule in [
        "Product trust boundary",
        "Dependencies point inward",
        "Unclassified future wire values degrade safely",
        "Keep owned Rust and prose within 100 columns",
    ] {
        assert!(body.contains(rule), "architecture guide lost rule: {rule}");
    }
}
fn source(relative: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn process_coordination_does_not_own_http_routes() {
    let main = source("src/main.rs");
    let code_lines = main
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with("//!") && !line.starts_with("//")
        })
        .count();
    assert!(
        !main.contains("Router::new") && !main.contains(".route("),
        "src/main.rs must delegate HTTP surface construction to router.rs"
    );
    assert!(
        code_lines <= 6 && main.contains("reproit_cloud::run().await"),
        "src/main.rs must remain a thin delegate to the library application"
    );
    assert!(
        source("src/lib.rs").contains("router::build(app)"),
        "src/lib.rs must construct the HTTP surface through router::build"
    );
}

// The ranking/resolution spine is documented as PURE transforms over signals a
// handler already fetched (impact.rs, buckets.rs, cohorts.rs, resolution.rs):
// that purity is what makes them unit-testable with no DB/HTTP and their
// output reproducible. Encode it so a convenient sqlx import cannot silently
// break the contract.
#[test]
fn pure_ranking_modules_stay_db_free() {
    for relative in [
        "src/ingest/impact.rs",
        "src/ingest/buckets.rs",
        "src/ingest/cohorts.rs",
        "src/triage/resolution.rs",
    ] {
        let body = source(relative);
        for forbidden in ["sqlx", "crate::db"] {
            assert!(
                !body.contains(forbidden),
                "{relative} reaches the database through {forbidden}; keep it a pure transform \
                 and fetch in the handler"
            );
        }
    }
}

#[test]
fn responsibility_heavy_modules_stay_split() {
    for (relative, max_lines) in [
        ("src/main.rs", 20),
        ("src/lib.rs", 1_200),
        ("src/http_security.rs", 600),
        ("src/operations.rs", 400),
        ("src/router.rs", 500),
        ("src/ingest/mod.rs", 1_000),
        ("src/ingest/bucket_api.rs", 600),
        ("src/ingest/tests.rs", 600),
        ("src/ingest/aggregation.rs", 300),
        ("src/ingest/evidence.rs", 300),
        ("src/ingest/export.rs", 300),
        ("src/ingest/replay.rs", 300),
    ] {
        let lines = source(relative).lines().count();
        assert!(
            lines <= max_lines,
            "{relative} has {lines} lines; split its next responsibility before {max_lines}"
        );
    }
}
