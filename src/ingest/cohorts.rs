//! Cohort / discriminator analysis: the pure functions behind the "happens to
//! some users, not others" answer.
//!
//! Given an error cohort's PII-safe context maps and the app baseline, surface
//! the dimensions over-represented in the cohort (`discriminators`), then turn a
//! finding's discriminator + input fingerprint into a `fixtureSpec` a property-
//! matched replay can synthesize from (`fixture_spec`). Nothing here touches the
//! DB or generates data; these are deterministic, side-effect-free transforms.

use serde_json::{json, Map, Value};

pub type ValueCounts = std::collections::BTreeMap<String, usize>;
pub type ContextCounts = std::collections::BTreeMap<String, ValueCounts>;

/// k-anonymity floor for cohort analysis. A discriminator is only surfaced when
/// at least this many cohort members share it, so a reported dimension always
/// describes a GROUP, never an individual. Without this, a one-person cohort
/// yields `{plan: enterprise, locale: fr-CA, role: admin}` at lift `inf`, which
/// is itself a quasi-identifier even though no single field is PII. 5 is the
/// conservative floor; raise it for higher-sensitivity tenants.
pub const K_ANON: usize = 5;

/// Turn a finding's discriminator + PII-safe input fingerprint into a
/// `fixtureSpec`: a JSON description of the conditions a property-matched replay
/// should synthesize to reproduce a data-specific bug.
///
/// Inputs:
/// - `context`: the error's PII-safe context. May carry `context.fingerprint`,
///   an array of per-field derived features the SDK emits, e.g.
///   `{field, len, charset: ascii|numeric|unicode, hasEmoji, isEmpty, isRtl}`.
/// - `discriminators`: the dimensions over-represented among users who hit this
///   bug (output of `discriminators()`), e.g. `[{key:"locale", value:"tr", ..}]`.
///
/// Output shape (example):
///   discriminator locale=tr + fingerprint {field:"name", len:312,
///   charset:"unicode", hasEmoji:true}
///   -> {"locale":"tr", "inputs":[{"field":"name",
///         "generate":{"minLen":312, "charset":"unicode", "emoji":true}}]}
/// Richer fingerprints may also emit `minBytes`, `minGraphemes`, `scripts`,
/// `combining`, `zeroWidth`, `newline`, and `edgeWhitespace`; the CLI
/// synthesizer consumes the same directive vocabulary.
///
/// Tolerates a missing/empty fingerprint gracefully (the `inputs` array is just
/// empty). A spec with no locale discriminator and no fingerprint is `{}`.
///
/// HONEST: this produces the SPEC only. reproit's `fixture::synthesize` is what
/// turns it into concrete matching input data, and the explorer types that into
/// matching fields during replay; nothing here generates data or runs anything.
pub fn fixture_spec(context: &Map<String, Value>, discriminators: &[Value]) -> Value {
    let mut spec = Map::new();

    // Promote scalar discriminator dimensions (locale, plan, role, ...) into the
    // top level of the spec so the synthesizer pins them. We only lift simple
    // string-valued discriminators; the fingerprint drives the input fields.
    for d in discriminators {
        let (Some(key), Some(val)) = (
            d.get("key").and_then(|v| v.as_str()),
            d.get("value").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        // `fingerprint` is structured input data, never a scalar dimension to pin.
        if key == "fingerprint" {
            continue;
        }
        spec.entry(key.to_string()).or_insert_with(|| json!(val));
    }

    // Map each fingerprinted field to a generation directive.
    let inputs: Vec<Value> = context
        .get("fingerprint")
        .and_then(|v| v.as_array())
        .map(|fields| fields.iter().filter_map(field_to_input).collect())
        .unwrap_or_default();
    spec.insert("inputs".to_string(), json!(inputs));

    Value::Object(spec)
}

/// Convert one fingerprint field entry into a `{field, generate:{...}}` directive
/// for the synthesizer. Returns `None` for an entry without a usable `field`.
fn field_to_input(fp: &Value) -> Option<Value> {
    let field = fp.get("field").and_then(|v| v.as_str())?;
    let mut generate = Map::new();
    // Length: ask the synthesizer for at least the observed length so it
    // reproduces overflow/truncation bugs that need a long enough value.
    if let Some(len) = fp.get("len").and_then(|v| v.as_u64()) {
        generate.insert("minLen".to_string(), json!(len));
    }
    if let Some(charset) = fp.get("charset").and_then(|v| v.as_str()) {
        generate.insert("charset".to_string(), json!(charset));
    }
    if fp
        .get("hasEmoji")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        generate.insert("emoji".to_string(), json!(true));
    }
    if fp.get("isRtl").and_then(|v| v.as_bool()).unwrap_or(false) {
        generate.insert("rtl".to_string(), json!(true));
    }
    if fp.get("isEmpty").and_then(|v| v.as_bool()).unwrap_or(false) {
        generate.insert("empty".to_string(), json!(true));
    }
    // Richer PII-safe features (fp v2). All optional; only emitted when present
    // or true, so older v1 fingerprints (len/charset/emoji/rtl/empty) are
    // unaffected. These split bug classes the v1 set conflated:
    //   - bytes vs graphemes vs len: UTF-8 byte limits (DB varchar) vs grapheme
    //     count (layout) vs code points (indexing) are three distinct overflows.
    //   - scripts: mixed-script bidi bugs need >1 script, which `rtl` alone
    //     can't express.
    //   - combining/zeroWidth/newline/edgeWhitespace: the classic render,
    //     normalization, injection, and trim breakers.
    if let Some(bytes) = fp.get("bytes").and_then(|v| v.as_u64()) {
        generate.insert("minBytes".to_string(), json!(bytes));
    }
    if let Some(graphemes) = fp.get("graphemes").and_then(|v| v.as_u64()) {
        generate.insert("minGraphemes".to_string(), json!(graphemes));
    }
    if let Some(scripts) = fp.get("scripts").and_then(|v| v.as_array()) {
        if !scripts.is_empty() {
            generate.insert("scripts".to_string(), json!(scripts));
        }
    }
    for (fp_key, gen_key) in [
        ("hasCombiningMarks", "combining"),
        ("hasZeroWidth", "zeroWidth"),
        ("hasNewline", "newline"),
        ("leadingTrailingWhitespace", "edgeWhitespace"),
    ] {
        if fp.get(fp_key).and_then(|v| v.as_bool()).unwrap_or(false) {
            generate.insert(gen_key.to_string(), json!(true));
        }
    }
    Some(json!({ "field": field, "generate": Value::Object(generate) }))
}

/// Count string-rendered values of `key` across a set of context maps.
fn value_counts(
    rows: &[Map<String, Value>],
    key: &str,
) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for r in rows {
        if let Some(v) = r.get(key) {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            *counts.entry(s).or_insert(0) += 1;
        }
    }
    counts
}

fn cohort_value(key: &str, v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Object(o) if key == "build" => o
            .get("version")
            .or_else(|| o.get("commit"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
        _ => None,
    }
}

pub fn dimension_values(context: &Map<String, Value>) -> Vec<(String, String)> {
    context
        .iter()
        .filter(|(key, _)| safe_cohort_key(key))
        .filter_map(|(key, value)| cohort_value(key, value).map(|value| (key.clone(), value)))
        .collect()
}

pub fn discriminators_from_counts(
    cohort_n: usize,
    cohort: &ContextCounts,
    baseline_n: usize,
    baseline: &ContextCounts,
) -> Vec<Value> {
    if cohort_n < K_ANON {
        return Vec::new();
    }
    let cohort_n = cohort_n as f64;
    let baseline_n = baseline_n.max(1) as f64;
    let mut out: Vec<(f64, f64, Value)> = Vec::new();
    for (key, values) in cohort {
        for (value, count) in values {
            let cohort_share = *count as f64 / cohort_n;
            let base_count = baseline
                .get(key)
                .and_then(|counts| counts.get(value))
                .copied()
                .unwrap_or(0);
            let baseline_share = base_count as f64 / baseline_n;
            let finite_lift = baseline_share > 0.0;
            let lift = if finite_lift {
                cohort_share / baseline_share
            } else {
                f64::INFINITY
            };
            if cohort_share >= 0.5 && lift >= 1.5 && *count >= K_ANON {
                out.push((
                    cohort_share,
                    lift,
                    json!({
                        "key": key,
                        "value": value,
                        "cohortShare": (cohort_share * 100.0).round() / 100.0,
                        "baselineShare": (baseline_share * 100.0).round() / 100.0,
                        "lift": if finite_lift { json!((lift * 100.0).round() / 100.0) } else { json!("inf") },
                    }),
                ));
            }
        }
    }
    out.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });
    out.into_iter().map(|(_, _, value)| value).collect()
}

fn safe_cohort_key(key: &str) -> bool {
    !matches!(key, "fingerprint" | "input" | "inputs")
}

fn display_key_rank(key: &str) -> usize {
    [
        "browser", "locale", "plan", "build", "os", "device", "platform", "role", "route",
    ]
    .iter()
    .position(|k| *k == key)
    .unwrap_or(usize::MAX)
}

fn display_counts(
    rows: &[Map<String, Value>],
    key: &str,
) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for r in rows {
        if let Some(v) = r.get(key).and_then(|v| cohort_value(key, v)) {
            *counts.entry(v).or_insert(0) += 1;
        }
    }
    counts
}

/// Histogram-friendly cohort cards for the detailed bucket view.
///
/// Unlike `discriminators`, this is not an assertion that a dimension is the root
/// cause. It is the ordinary distribution of PII-safe context dimensions for the
/// bucket, compared with the app baseline, so the dashboard always has a useful
/// detailed view even when no over-baseline discriminator is strong enough to
/// call out.
pub fn cohort_breakdowns(
    cohort: &[Map<String, Value>],
    baseline: &[Map<String, Value>],
) -> Vec<Value> {
    if cohort.is_empty() {
        return Vec::new();
    }
    let cohort_n = cohort.len() as f64;
    let base_n = baseline.len().max(1) as f64;
    let mut keys = std::collections::BTreeSet::new();
    for r in cohort.iter().chain(baseline.iter()) {
        for k in r.keys() {
            if safe_cohort_key(k) && r.get(k).and_then(|v| cohort_value(k, v)).is_some() {
                keys.insert(k.clone());
            }
        }
    }
    let mut cards: Vec<Value> = keys
        .into_iter()
        .filter_map(|key| {
            let cohort_counts = display_counts(cohort, &key);
            if cohort_counts.is_empty() {
                return None;
            }
            let base_counts = display_counts(baseline, &key);
            let mut values: Vec<String> = cohort_counts
                .keys()
                .chain(base_counts.keys())
                .cloned()
                .collect();
            values.sort();
            values.dedup();
            values.sort_by(|a, b| {
                let ac = *cohort_counts.get(a).unwrap_or(&0);
                let bc = *cohort_counts.get(b).unwrap_or(&0);
                let ab = *base_counts.get(a).unwrap_or(&0);
                let bb = *base_counts.get(b).unwrap_or(&0);
                bc.cmp(&ac).then(bb.cmp(&ab)).then(a.cmp(b))
            });
            let values: Vec<Value> = values
                .into_iter()
                .take(4)
                .map(|value| {
                    let count = *cohort_counts.get(&value).unwrap_or(&0);
                    let base_count = *base_counts.get(&value).unwrap_or(&0);
                    let cohort_share = count as f64 / cohort_n;
                    let baseline_share = base_count as f64 / base_n;
                    let finite_lift = baseline_share > 0.0;
                    let lift = if finite_lift {
                        cohort_share / baseline_share
                    } else {
                        f64::INFINITY
                    };
                    json!({
                        "value": value,
                        "count": count,
                        "cohortShare": (cohort_share * 100.0).round() / 100.0,
                        "baselineShare": (baseline_share * 100.0).round() / 100.0,
                        "lift": if finite_lift { json!((lift * 100.0).round() / 100.0) } else { json!("inf") },
                    })
                })
                .collect();
            Some(json!({
                "key": key,
                "total": cohort.len(),
                "values": values,
            }))
        })
        .collect();
    cards.sort_by(|a, b| {
        let ak = a["key"].as_str().unwrap_or("");
        let bk = b["key"].as_str().unwrap_or("");
        display_key_rank(ak)
            .cmp(&display_key_rank(bk))
            .then(ak.cmp(bk))
    });
    cards
}

/// Context dimensions over-represented in `cohort` vs `baseline`. A (key,value)
/// is a discriminator when it dominates the cohort (>=50%), is enriched vs
/// baseline (lift >= 1.5), AND is shared by at least `K_ANON` cohort members
/// (so it describes a group, never an individual). Sorted by cohort share then
/// lift. The classic "100% of failures have locale=tr" surfaces here
/// automatically, but only once enough users hit it to be non-identifying.
///
/// PRIVACY: cohorts below `K_ANON` yield nothing at all. A discriminator over a
/// tiny cohort is a quasi-identifier (the one enterprise/fr-CA/admin user), so
/// we suppress rather than risk re-identification.
pub fn discriminators(
    cohort: &[Map<String, Value>],
    baseline: &[Map<String, Value>],
) -> Vec<Value> {
    // k-anonymity: too small a cohort can't yield a non-identifying discriminator.
    if cohort.len() < K_ANON {
        return Vec::new();
    }
    let cohort_n = cohort.len() as f64;
    let base_n = baseline.len().max(1) as f64;
    let mut keys = std::collections::BTreeSet::new();
    for c in cohort {
        for k in c.keys() {
            keys.insert(k.clone());
        }
    }
    let mut out: Vec<(f64, f64, Value)> = Vec::new();
    for key in keys {
        let cohort_vals = value_counts(cohort, &key);
        let base_vals = value_counts(baseline, &key);
        for (val, cn) in &cohort_vals {
            let cohort_share = *cn as f64 / cohort_n;
            let base_share = *base_vals.get(val).unwrap_or(&0) as f64 / base_n;
            let finite_lift = base_share > 0.0;
            let lift = if finite_lift {
                cohort_share / base_share
            } else {
                f64::INFINITY
            };
            // The value must be held by >= K_ANON cohort members (not just
            // dominate a tiny cohort), else surfacing it could single out a user.
            if cohort_share >= 0.5 && lift >= 1.5 && *cn >= K_ANON {
                out.push((
                    cohort_share,
                    lift,
                    json!({
                        "key": key,
                        "value": val,
                        "cohortShare": (cohort_share * 100.0).round() / 100.0,
                        "baselineShare": (base_share * 100.0).round() / 100.0,
                        "lift": if finite_lift { json!((lift * 100.0).round() / 100.0) } else { json!("inf") },
                    }),
                ));
            }
        }
    }
    out.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });
    out.into_iter().map(|(_, _, v)| v).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect()
    }

    #[test]
    fn surfaces_the_dominant_enriched_dimension() {
        // Every user who hit this bug is locale=tr; the app overall is mostly en.
        // The cohort is >= K_ANON so the discriminator is non-identifying.
        let cohort = vec![ctx(&[("locale", "tr")]); 5];
        let mut baseline = vec![ctx(&[("locale", "en")]); 10];
        baseline.extend(vec![ctx(&[("locale", "tr")]); 5]);
        let d = discriminators(&cohort, &baseline);
        assert!(!d.is_empty(), "should find a discriminator");
        assert_eq!(d[0]["key"], "locale");
        assert_eq!(d[0]["value"], "tr");
        assert_eq!(d[0]["cohortShare"], json!(1.0));
    }

    #[test]
    fn suppresses_small_cohorts_for_k_anonymity() {
        // A 2-person cohort with a perfectly enriched (lift inf) dimension must
        // yield NOTHING: the discriminator would re-identify those two users.
        let cohort = vec![
            ctx(&[
                ("plan", "enterprise"),
                ("locale", "fr-CA"),
                ("role", "admin"),
            ]),
            ctx(&[
                ("plan", "enterprise"),
                ("locale", "fr-CA"),
                ("role", "admin"),
            ]),
        ];
        let baseline = vec![ctx(&[("plan", "free"), ("locale", "en"), ("role", "user")]); 50];
        assert!(
            discriminators(&cohort, &baseline).is_empty(),
            "a sub-K_ANON cohort must not surface any discriminator"
        );
    }

    #[test]
    fn requires_k_members_share_the_value() {
        // Cohort is big enough overall (8), but locale=tr is held by only 4
        // members (< K_ANON): dominant at 50% yet still suppressed, because 4
        // users is too few to be non-identifying.
        let mut cohort = vec![ctx(&[("locale", "tr")]); 4];
        cohort.extend(vec![ctx(&[("locale", "de")]); 4]);
        let baseline = vec![ctx(&[("locale", "en")]); 50];
        assert!(
            discriminators(&cohort, &baseline).is_empty(),
            "a value shared by < K_ANON members must be suppressed"
        );
        // Bump tr to 5 members (>= K_ANON) and it surfaces.
        let mut cohort = vec![ctx(&[("locale", "tr")]); 5];
        cohort.extend(vec![ctx(&[("locale", "de")]); 4]);
        let d = discriminators(&cohort, &baseline);
        assert!(d.iter().any(|x| x["value"] == "tr"));
    }

    #[test]
    fn field_to_input_v2_features_map_to_directives() {
        // A richer (fp v2) fingerprint: every new feature becomes a generate
        // directive, none of the PII is present.
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([{
                "field": "name",
                "len": 18, "bytes": 30, "graphemes": 14,
                "charset": "unicode",
                "scripts": ["Latin", "Arabic"],
                "hasEmoji": true, "isRtl": true,
                "hasCombiningMarks": true, "hasZeroWidth": true,
                "hasNewline": true, "leadingTrailingWhitespace": true
            }]),
        );
        let spec = fixture_spec(&context, &[]);
        let g = &spec["inputs"][0]["generate"];
        assert_eq!(g["minLen"], json!(18));
        assert_eq!(g["minBytes"], json!(30));
        assert_eq!(g["minGraphemes"], json!(14));
        assert_eq!(g["scripts"], json!(["Latin", "Arabic"]));
        assert_eq!(g["combining"], json!(true));
        assert_eq!(g["zeroWidth"], json!(true));
        assert_eq!(g["newline"], json!(true));
        assert_eq!(g["edgeWhitespace"], json!(true));
    }

    #[test]
    fn fixture_spec_v2_contract_matches_golden() {
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([{
                "field": "name",
                "len": 18,
                "bytes": 90,
                "graphemes": 24,
                "charset": "unicode",
                "scripts": ["Latin", "Arabic"],
                "hasEmoji": true,
                "isRtl": true,
                "hasCombiningMarks": true,
                "hasZeroWidth": true,
                "hasNewline": true,
                "leadingTrailingWhitespace": true
            }]),
        );
        let discs = vec![json!({ "key": "locale", "value": "tr" })];
        let expected: Value = serde_json::from_str(include_str!(
            "../../tests/golden/fixtures/fixture-spec-v2.json"
        ))
        .unwrap();
        assert_eq!(fixture_spec(&context, &discs), expected);
    }

    #[test]
    fn fixture_spec_v2_contract_matches_cli_mirror_when_checked_out() {
        let local = include_str!("../../tests/golden/fixtures/fixture-spec-v2.json");
        let sibling = std::path::Path::new(
            "../reproit-cli/crates/reproit/tests/golden/fixtures/fixture-spec-v2.json",
        );
        if sibling.exists() {
            let other = std::fs::read_to_string(sibling).unwrap();
            let local_json: Value = serde_json::from_str(local).unwrap();
            let other_json: Value = serde_json::from_str(&other).unwrap();
            assert_eq!(local_json, other_json);
        }
    }

    #[test]
    fn field_to_input_v1_fingerprint_is_unaffected() {
        // A v1 fingerprint (no new fields) produces only the v1 directives: the
        // new keys are absent, not emitted as false/empty.
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([{ "field": "name", "len": 10, "charset": "ascii" }]),
        );
        let g = fixture_spec(&context, &[])["inputs"][0]["generate"].clone();
        for absent in [
            "minBytes",
            "minGraphemes",
            "scripts",
            "combining",
            "zeroWidth",
            "newline",
            "edgeWhitespace",
        ] {
            assert!(
                g.get(absent).is_none(),
                "{absent} should be absent for a v1 fingerprint"
            );
        }
    }

    #[test]
    fn ignores_dimensions_that_match_the_baseline() {
        // platform=ios in the cohort but ios is also the baseline norm -> not a
        // discriminator (no enrichment).
        let cohort = vec![ctx(&[("platform", "ios")]), ctx(&[("platform", "ios")])];
        let baseline = vec![ctx(&[("platform", "ios")]); 10];
        let d = discriminators(&cohort, &baseline);
        assert!(d.is_empty(), "uniform dimension is not a discriminator");
    }

    #[test]
    fn cohort_breakdowns_render_detail_histograms_without_discriminators() {
        let cohort = vec![ctx(&[
            ("locale", "en-US"),
            ("plan", "pro"),
            ("platform", "web"),
        ])];
        let baseline = vec![
            ctx(&[("locale", "en-US"), ("plan", "pro"), ("platform", "web")]),
            ctx(&[("locale", "tr"), ("plan", "team"), ("platform", "ios")]),
        ];
        let cards = cohort_breakdowns(&cohort, &baseline);
        assert_eq!(cards[0]["key"], json!("locale"));
        assert_eq!(cards[0]["values"][0]["value"], json!("en-US"));
        assert_eq!(cards[0]["values"][0]["cohortShare"], json!(1.0));
        assert_eq!(cards[0]["values"][0]["baselineShare"], json!(0.5));
        assert!(
            cards.iter().any(|c| c["key"] == "platform"),
            "ordinary platform context should render even when no discriminator is safe"
        );
    }

    #[test]
    fn empty_cohort_has_no_discriminators() {
        assert!(discriminators(&[], &[ctx(&[("a", "b")])]).is_empty());
    }

    #[test]
    fn fixture_spec_locale_tr_with_long_unicode_name() {
        // The motivating case: locale=tr discriminator + a long unicode name
        // field with an emoji. The synthesizer should pin tr and be told to make
        // a >=312-char unicode value with an emoji for the `name` field.
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([{
                "field": "name",
                "len": 312,
                "charset": "unicode",
                "hasEmoji": true,
                "isEmpty": false,
                "isRtl": false
            }]),
        );
        let discs = vec![json!({ "key": "locale", "value": "tr" })];
        let spec = fixture_spec(&context, &discs);
        assert_eq!(spec["locale"], json!("tr"));
        let inputs = spec["inputs"].as_array().expect("inputs array");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["field"], json!("name"));
        assert_eq!(inputs[0]["generate"]["minLen"], json!(312));
        assert_eq!(inputs[0]["generate"]["charset"], json!("unicode"));
        assert_eq!(inputs[0]["generate"]["emoji"], json!(true));
        // flags that were false are omitted, not emitted as false.
        assert!(inputs[0]["generate"].get("rtl").is_none());
        assert!(inputs[0]["generate"].get("empty").is_none());
    }

    #[test]
    fn fixture_spec_tolerates_missing_fingerprint() {
        // Discriminator present but no fingerprint: pin the dimension, empty
        // inputs, never panics.
        let context = ctx(&[("plan", "free")]);
        let discs = vec![json!({ "key": "plan", "value": "free" })];
        let spec = fixture_spec(&context, &discs);
        assert_eq!(spec["plan"], json!("free"));
        assert_eq!(spec["inputs"], json!([]));
    }

    #[test]
    fn fixture_spec_empty_when_nothing_to_match() {
        // No discriminators, no fingerprint -> just an empty inputs list.
        let spec = fixture_spec(&Map::new(), &[]);
        assert_eq!(spec, json!({ "inputs": [] }));
    }

    #[test]
    fn fixture_spec_multiple_fields_and_rtl_empty_flags() {
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([
                { "field": "bio", "len": 0, "charset": "ascii", "isEmpty": true },
                { "field": "city", "len": 8, "charset": "unicode", "isRtl": true }
            ]),
        );
        let spec = fixture_spec(&context, &[]);
        let inputs = spec["inputs"].as_array().expect("inputs array");
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0]["field"], json!("bio"));
        assert_eq!(inputs[0]["generate"]["empty"], json!(true));
        assert_eq!(inputs[0]["generate"]["minLen"], json!(0));
        assert_eq!(inputs[1]["field"], json!("city"));
        assert_eq!(inputs[1]["generate"]["rtl"], json!(true));
        assert_eq!(inputs[1]["generate"]["charset"], json!("unicode"));
    }

    #[test]
    fn fixture_spec_skips_fingerprint_discriminator_and_unusable_entries() {
        // A `fingerprint` keyed discriminator must not become a scalar pin, and a
        // fingerprint entry without a `field` is skipped, not fatal.
        let mut context = Map::new();
        context.insert(
            "fingerprint".to_string(),
            json!([
                { "len": 5, "charset": "ascii" },           // no field -> skipped
                { "field": "email", "len": 40, "charset": "ascii" }
            ]),
        );
        let discs = vec![
            json!({ "key": "fingerprint", "value": "x" }),
            json!({ "key": "locale", "value": "tr" }),
        ];
        let spec = fixture_spec(&context, &discs);
        assert!(spec.get("fingerprint").is_none());
        assert_eq!(spec["locale"], json!("tr"));
        let inputs = spec["inputs"].as_array().expect("inputs array");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0]["field"], json!("email"));
    }
}
